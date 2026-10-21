"""Read-only health orchestration: status, history refresh, metrics, verdicts.

Like :mod:`meshprovision.status.report` (whose :func:`~meshprovision.status.
report.run_status` it runs first), this module is **strictly read-only**
toward the database and every device: it loads the database and never
saves, replaces, upserts or deletes anything in it
(``tests/unit/test_readonly_status_boundary.py`` walks it for those
operations). Besides what ``mesh status`` writes (the HTTP cache, the
lorastats region list and memo), it writes only the per-node health
history files (:mod:`meshprovision.health.store`).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from meshprovision.datasources.lorastats_packets import LorastatsPackets
from meshprovision.errors import ExitCode
from meshprovision.health.history import NodeHistory
from meshprovision.health.metrics import NodeMetrics, compute_metrics
from meshprovision.health.refresh import HealthRefresher, RefreshFailure, RefreshOutcome
from meshprovision.health.rules import (
    Advice,
    Finding,
    Importance,
    NodeContext,
    Verdict,
    advise,
    assess,
    rank_importance,
)
from meshprovision.health.store import HISTORY_DIRNAME, HistoryStore
from meshprovision.nodeid import NodeId
from meshprovision.status.merge import MergedNode
from meshprovision.status.report import (
    SourceFailure,
    StatusOptions,
    StatusReport,
    build_report,
    load_records,
    run_status,
)

if TYPE_CHECKING:
    from meshprovision.cache.http import CachedHTTPClient
    from meshprovision.config.settings import Settings
    from meshprovision.datasources.lorastats_regions import RegionList

__all__ = [
    "DEFAULT_DAYS",
    "MAX_DAYS",
    "HealthOptions",
    "HealthReport",
    "NodeHealth",
    "StatusHealth",
    "assess_nodes",
    "assess_status",
    "run_health",
]

DEFAULT_DAYS: Final[int] = 7
"""The default window of ``mesh health``, in days."""

MAX_DAYS: Final[int] = 30
"""The longest window: the history keeps 30 days."""


@dataclass(frozen=True, slots=True)
class HealthOptions:
    """Everything that shapes one ``mesh health`` run.

    Attributes:
        days: The window, in days (1 to :data:`MAX_DAYS`).
        fetch: Whether to ask any source; ``False`` reads only the history.
        refresh: Refresh even within the 10-minute interval (still at
            most once a minute per node).
        gateway_checks: Also check what each node uplinked as a gateway.
        node_ids: Which nodes to report on; empty means every active one.
        regions: The lorastats regions (as for ``mesh status``).
        region_list: Where the regions come from when none are given.
        force_refresh: Bypass the HTTP cache for ``mesh status``'s requests.
    """

    days: int = DEFAULT_DAYS
    fetch: bool = True
    refresh: bool = False
    gateway_checks: bool = False
    node_ids: tuple[NodeId, ...] = ()
    regions: tuple[str, ...] = ()
    region_list: RegionList | None = None
    force_refresh: bool = False


@dataclass(frozen=True, slots=True)
class NodeHealth:
    """One node's health.

    Attributes:
        node: Its ``mesh status`` view (names, role, last seen, battery).
        metrics: Its metrics over the window.
        verdict: Its verdict.
        findings: The reasons for it.
        importance: How much our other nodes rely on it.
        advice: Configuration changes worth considering.
        role: Its role, from the sources, its node info or the database.
        history_fetched_at: When its history was last refreshed.
    """

    node: MergedNode
    metrics: NodeMetrics
    verdict: Verdict
    findings: tuple[Finding, ...]
    importance: Importance
    advice: tuple[Advice, ...]
    role: str | None
    history_fetched_at: float | None


@dataclass(frozen=True, slots=True)
class HealthReport:
    """The result of one ``mesh health`` run.

    Attributes:
        generated_at: When it was assembled (timezone-aware).
        days: The window, in days.
        fetched: Whether any source was asked.
        nodes: Every reported node's health, in database order.
        status: The ``mesh status`` report behind it (``None`` without fetching).
        refresh: What the history refresh did (``None`` without fetching).
        network_requests: Network requests made by the whole run.
    """

    generated_at: datetime
    days: int
    fetched: bool
    nodes: tuple[NodeHealth, ...]
    status: StatusReport | None = None
    refresh: RefreshOutcome | None = None
    network_requests: int = 0

    @property
    def source_failures(self) -> tuple[SourceFailure, ...]:
        """The ``mesh status`` sources that failed."""
        return () if self.status is None else self.status.failures

    @property
    def refresh_failures(self) -> tuple[RefreshFailure, ...]:
        """The nodes whose history refresh failed."""
        return () if self.refresh is None else self.refresh.failures

    def exit_code(self) -> int:
        """The exit code: :attr:`ExitCode.STATUS_DEGRADED` on a critical node or any failure.

        Returns:
            7 when any node's verdict is critical or any source or refresh
            failed, else 0.
        """
        critical = any(node.verdict is Verdict.CRIT for node in self.nodes)
        if critical or self.source_failures or self.refresh_failures:
            return int(ExitCode.STATUS_DEGRADED)
        return int(ExitCode.OK)


def _epoch(value: datetime | None) -> float | None:
    """Return a timestamp as epoch seconds."""
    return None if value is None else value.timestamp()


def _role(node: MergedNode, history: NodeHistory) -> str | None:
    """Pick a node's role: the sources', else its node info's, else the database's."""
    if node.role:
        return node.role
    if history.nodeinfo is not None and history.nodeinfo.role:
        return history.nodeinfo.role
    return node.record.role if node.record is not None and node.record.role else None


def assess_nodes(
    nodes: Sequence[MergedNode],
    histories: Mapping[NodeId, NodeHistory],
    *,
    fleet: Sequence[NodeId],
    now: float,
    days: int,
) -> tuple[NodeHealth, ...]:
    """Judge each reported node's health from its history. Pure.

    Args:
        nodes: The reported nodes' ``mesh status`` views, in output order.
        histories: Every fleet node's history (a missing one is empty).
        fleet: Our nodes: their histories decide importance and which
            relay bytes can be attributed.
        now: The window's end, epoch seconds.
        days: The window, in days.

    Returns:
        One :class:`NodeHealth` per reported node, in ``nodes`` order.
    """
    everyone = tuple(dict.fromkeys((*fleet, *(node.node_id for node in nodes))))

    def history_of(node_id: NodeId) -> NodeHistory:
        return histories.get(node_id) or NodeHistory(node=node_id)

    metrics = {
        node_id: compute_metrics(history_of(node_id), now=now, days=days, fleet=everyone)
        for node_id in everyone
    }
    roles = {node.node_id: _role(node, history_of(node.node_id)) for node in nodes}
    importance = rank_importance(metrics, roles)
    result = []
    for node in nodes:
        role = roles[node.node_id]
        context = NodeContext(
            role=role,
            last_seen=_epoch(node.last_seen),
            battery=node.battery_level,
            battery_time=_epoch(node.last_device_metrics),
        )
        verdict, findings = assess(metrics[node.node_id], context)
        result.append(
            NodeHealth(
                node=node,
                metrics=metrics[node.node_id],
                verdict=verdict,
                findings=findings,
                importance=importance[node.node_id],
                advice=advise(metrics[node.node_id], context, importance[node.node_id]),
                role=role,
                history_fetched_at=history_of(node.node_id).fetched_at,
            )
        )
    return tuple(result)


def _refresh(
    refresher: HealthRefresher, nodes: Sequence[MergedNode], *, gateway_check: bool
) -> RefreshOutcome:
    """Refresh the histories of ``nodes``, in the region lorastats found each in."""
    return refresher.refresh(
        [(node.node_id, node.lorastats_region) for node in nodes],
        boots={
            node.node_id: node.last_boot.timestamp() for node in nodes if node.last_boot is not None
        },
        gateway_check=gateway_check,
    )


@dataclass(frozen=True, slots=True)
class StatusHealth:
    """The health columns of ``mesh status --detail full``.

    Attributes:
        days: The window, in days.
        nodes: Each reported node's health.
        refresh: What the history refresh did.
        network_requests: Network requests the refresh made.
    """

    days: int
    nodes: Mapping[NodeId, NodeHealth]
    refresh: RefreshOutcome
    network_requests: int


def assess_status(
    report: StatusReport,
    refresher: HealthRefresher,
    *,
    client: CachedHTTPClient,
    days: int = DEFAULT_DAYS,
) -> StatusHealth:
    """Refresh and judge the nodes of a ``mesh status`` report (``--detail full``).

    The reported nodes are the fleet. Costs what
    :mod:`meshprovision.health.refresh` documents per due node, never a
    gateway check.

    Args:
        report: The status report.
        refresher: The refresher (one per process, shared by ``--watch`` polls).
        client: The HTTP client the refresher uses, to count its requests.
        days: The window, in days.

    Returns:
        The health of every reported node.
    """
    before = client.stats.network_requests
    outcome = _refresh(refresher, report.nodes, gateway_check=False)
    fleet = tuple(node.node_id for node in report.nodes)
    healths = assess_nodes(
        report.nodes,
        outcome.histories,
        fleet=fleet,
        now=datetime.now(tz=UTC).timestamp(),
        days=days,
    )
    return StatusHealth(
        days=days,
        nodes={health.node.node_id: health for health in healths},
        refresh=outcome,
        network_requests=client.stats.network_requests - before,
    )


def run_health(
    settings: Settings,
    options: HealthOptions,
    *,
    client: CachedHTTPClient,
    refresher: HealthRefresher | None = None,
) -> HealthReport:
    """Run one ``mesh health``: status, history refresh, assessment.

    With ``options.fetch``, runs ``mesh status``'s collection for the
    reported nodes (its own request budget), then refreshes the history of
    every reported node lorastats found (see
    :mod:`meshprovision.health.refresh` for that budget). Without, it asks
    nothing and reads only the database and the histories.

    Args:
        settings: Application settings (database path, cache directory).
        options: Options shaping this run.
        client: The HTTP client; this function does not close it.
        refresher: The refresher to use (one keeps its refresh times for
            the process); ``None`` builds one.

    Returns:
        The assembled report.

    Raises:
        meshprovision.errors.MissingContactError: If fetching and
            ``MESHPROVISION_CONTACT`` is unset.
        meshprovision.errors.DbError: If the database cannot be loaded.
    """
    records = load_records(settings.db_path)
    active = tuple(node_id for node_id, record in records.items() if not record.is_archived)
    ids = options.node_ids or active
    store = HistoryStore(settings.cache_dir / HISTORY_DIRNAME)
    before = client.stats.network_requests
    status: StatusReport | None = None
    outcome: RefreshOutcome | None = None
    if options.fetch:
        status = run_status(
            settings,
            StatusOptions(
                force_refresh=options.force_refresh,
                regions=options.regions,
                node_ids=ids,
                region_list=options.region_list,
            ),
            client=client,
        )
        nodes = status.nodes
        active_refresher = refresher or HealthRefresher(
            store, LorastatsPackets(client), force=options.refresh
        )
        outcome = _refresh(active_refresher, nodes, gateway_check=options.gateway_checks)
        refreshed: Mapping[NodeId, NodeHistory] = outcome.histories
    else:
        nodes = build_report(
            records=records,
            observations_by_source={},
            node_ids=ids,
            now=datetime.now(tz=UTC),
        ).nodes
        refreshed = {}
    fleet = tuple(dict.fromkeys((*active, *ids)))
    histories = {
        node_id: refreshed[node_id] if node_id in refreshed else store.load(node_id)
        for node_id in fleet
    }
    generated_at = datetime.now(tz=UTC)
    return HealthReport(
        generated_at=generated_at,
        days=options.days,
        fetched=options.fetch,
        nodes=assess_nodes(
            nodes, histories, fleet=fleet, now=generated_at.timestamp(), days=options.days
        ),
        status=status,
        refresh=outcome,
        network_requests=client.stats.network_requests - before,
    )
