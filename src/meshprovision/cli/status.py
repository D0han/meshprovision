"""``mesh status`` -- strictly read-only network health reporting.

This module MUST NOT reference ``OdsDatabase``, ``NodeRepository``,
``KeyRepository``, ``atomic_writer``, ``known_good``, ``pending_keys``,
``meshprovision.provisioning.apply``, ``meshprovision.provisioning.device_write``,
``meshprovision.provisioning.repair``,
:meth:`meshprovision.cli.common.CliContext.open_database`, or any
``save``/``replace``/``upsert``/``delete`` name. Everything flows through
:func:`meshprovision.status.report.run_status`, which is itself certified
read-only (an e2e test asserts the **live** ODS file's mtime is unchanged
across a full ``mesh status`` run). This module docstring restates that
guarantee so a future reader does not have to rediscover it.

The one exception: a successful load also best-effort refreshes the
known-good safety copy in a ``backups/`` directory next to the database
(see :func:`meshprovision.db.known_good.refresh_known_good`, wired in at
:func:`meshprovision.db.ods.load_database`) -- a side-channel copy, never
a write to the live database file itself, so it does not affect the
mtime guarantee above.

``--detail full`` also refreshes and judges each node's health through
:func:`meshprovision.health.report.assess_status`, and the plain table
refreshes histories over an hour old for its trend arrows
(:func:`meshprovision.health.report.refresh_status_histories`); both write
only the per-node health history files in the cache directory.
"""

from __future__ import annotations

import dataclasses
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Final, NoReturn

import click

from meshprovision.cli.common import (
    CONTEXT_SETTINGS,
    expected_interval_option,
    finite_float_callback,
    handle_cli_errors,
    node_ids_callback,
    pass_cli,
    template_hints,
)
from meshprovision.cli.help_format import MeshCommand
from meshprovision.datasources.base import SOURCE_LORANET, SOURCE_LORASTATS
from meshprovision.datasources.lorastats_packets import LorastatsPackets
from meshprovision.datasources.lorastats_regions import RegionList
from meshprovision.errors import DbError, ExitCode, SettingsError, exit_code_for
from meshprovision.health import render as health_render
from meshprovision.health.refresh import STATUS_REFRESH_INTERVAL_SECONDS, HealthRefresher
from meshprovision.health.report import assess_status, refresh_status_histories, rejudged_nodes
from meshprovision.health.store import HISTORY_DIRNAME, HistoryStore
from meshprovision.nodeid import NodeId
from meshprovision.status import render
from meshprovision.status.merge import (
    DEFAULT_OFFLINE_AFTER,
    DEFAULT_STALE_AFTER,
    SOURCE_PRIORITY,
    Thresholds,
)
from meshprovision.status.report import StatusOptions, StatusReport, run_status
from meshprovision.status.trend import load_trends

if TYPE_CHECKING:
    from meshprovision.cache.http import CachedHTTPClient
    from meshprovision.cli.common import CliContext

__all__ = ["status"]

DETAIL_BRIEF: Final[str] = "brief"
DETAIL_DEFAULT: Final[str] = "default"
DETAIL_FULL: Final[str] = "full"
DETAIL_LEVELS: Final[tuple[str, ...]] = (DETAIL_BRIEF, DETAIL_DEFAULT, DETAIL_FULL)
"""``--detail`` levels: ``default`` is the table as it always was."""

_MIN_WATCH_POLL_SECONDS = 5.0
"""Floor applied to the default watch-poll interval when no ``--interval`` is given."""

_MAX_WATCH_POLL_SECONDS = 604_800.0
"""Upper bound on the ``--watch`` poll interval, in seconds (one week).

Bounds ``--interval`` and caps the cache-TTL default too, since a TTL may
legitimately be huge or infinite ("never expire") while ``time.sleep``
overflows past about 9.2e9 seconds."""

_MAX_THRESHOLD_HOURS = 1_000_000.0
"""Upper bound on ``--stale-after``/``--offline-after``, in hours (about 114 years).

Any longer threshold already means "never" for a mesh node; the bound
keeps the value convertible to a :class:`~datetime.timedelta`, which
overflows past about 2.4e10 hours."""

_WATCH_MAX_CONSECUTIVE_DB_FAILURES = 3
"""How many consecutive per-poll :class:`~meshprovision.errors.DbError`\\ s
``--watch`` tolerates before giving up and exiting.

A single poll's database reload can fail transiently (a concurrent
``mesh db restore``, a non-atomic external save, a brief ``EACCES`` while
file ownership is being fixed) without the long-running monitor itself
being broken. A run of consecutive failures, though, means the database
is not coming back, and the monitor should stop rather than poll forever
in silence."""


def _build_options(
    *,
    nodes: tuple[NodeId, ...],
    sources: tuple[str, ...],
    regions: tuple[str, ...],
    configured_regions: tuple[str, ...] | None,
    refresh_regions: bool,
    stale_after: float | None,
    offline_after: float | None,
    force_refresh: bool,
    expected_interval: float | None = None,
    template_interval: timedelta | None = None,
    template_preset: str | None = None,
) -> StatusOptions:
    """Build a validated :class:`StatusOptions` from raw CLI values.

    Args:
        nodes: Node ids from ``--node``, already parsed by
            :func:`~meshprovision.cli.common.node_ids_callback`. Empty
            means every node in the database.
        sources: Data source names from ``--source``. Empty means every
            configured source.
        regions: lorastats region codes from ``--region``. Empty means
            ``configured_regions``.
        configured_regions: The ``MESHPROVISION_LORASTATS_REGIONS``
            setting. ``None`` means the region list read from
            lorastats.pl (see
            :mod:`~meshprovision.datasources.lorastats_regions`), loaded
            once for every poll of this process.
        refresh_regions: Whether to request that list again even while
            the cached one is fresh, from ``--refresh-regions``.
        stale_after: Hours from ``--stale-after``, or ``None`` for the
            default.
        offline_after: Hours from ``--offline-after``, or ``None`` for the
            default.
        force_refresh: Whether to bypass the HTTP cache read, from the
            global ``--no-cache``/``--force-refresh``.
        expected_interval: Hours from ``--expected-interval``, or ``None``
            to resolve each node's interval.
        template_interval: The template's node-info interval, the
            template-managed nodes' (see
            :func:`~meshprovision.cli.common.template_hints`).
        template_preset: The template's modem preset, likewise.

    Returns:
        The validated :class:`~meshprovision.status.report.StatusOptions`.

    Raises:
        SettingsError: If the resolved thresholds are not strictly
            ordered (``stale_after < offline_after``), or
            ``refresh_regions`` is given while regions are configured.

    A duplicate or equivalently-spelled id (``--node deadbe01 --node
    '!deadbe01'``) is de-duplicated here, preserving first-seen order --
    without this, the same node would be reported twice and double-
    counted in :attr:`~meshprovision.status.report.StatusReport.counts`.
    Done here rather than in :func:`~meshprovision.status.merge.merge_all`,
    whose "one node per entry, never re-sorts" contract other callers
    rely on and is worth keeping literal.
    """
    stale_hours = (
        stale_after if stale_after is not None else DEFAULT_STALE_AFTER.total_seconds() / 3600
    )
    offline_hours = (
        offline_after if offline_after is not None else DEFAULT_OFFLINE_AFTER.total_seconds() / 3600
    )
    try:
        thresholds = Thresholds.from_hours(stale_hours, offline_hours)
    except ValueError as exc:
        raise SettingsError(
            str(exc), hint="--stale-after must be strictly less than --offline-after."
        ) from exc

    node_ids = tuple(dict.fromkeys(nodes))
    resolved_regions = tuple(regions) or configured_regions or ()
    if refresh_regions and resolved_regions:
        raise SettingsError(
            "--refresh-regions has no effect: the lorastats regions are configured.",
            hint="Drop --region and MESHPROVISION_LORASTATS_REGIONS to use lorastats.pl's list.",
        )

    return StatusOptions(
        thresholds=thresholds,
        force_refresh=force_refresh,
        sources=tuple(sources) or SOURCE_PRIORITY,
        regions=resolved_regions,
        node_ids=node_ids,
        region_list=None if resolved_regions else RegionList(refresh=refresh_regions),
        expected_interval=None if expected_interval is None else timedelta(hours=expected_interval),
        template_interval=template_interval,
        template_preset=template_preset,
    )


@dataclass(frozen=True, slots=True)
class _Detail:
    """How much ``--detail`` shows, and what ``full`` refreshes with.

    Attributes:
        level: ``brief``, ``default`` or ``full``.
        refresher: For ``full``: one refresher for every poll, so a node's
            history is refreshed at most once per its interval.
        client: The client the refreshers use.
        stale_refresher: Without ``full``: refreshes only histories older than
            an hour, for the trend arrows; ``None`` for no refresh.
    """

    level: str = DETAIL_DEFAULT
    refresher: HealthRefresher | None = None
    client: CachedHTTPClient | None = None
    stale_refresher: HealthRefresher | None = None


_DEFAULT_DETAIL: Final[_Detail] = _Detail()
"""The plain table (``--detail default``), with nothing to refresh."""


def _emit(
    ctx: CliContext,
    report: StatusReport,
    *,
    json_output: bool,
    detail: _Detail = _DEFAULT_DETAIL,
) -> StatusReport:
    """Emit one status report to the appropriate stream.

    A history refresh (``--detail full``, or the plain table's refresh of
    stale histories) re-judges the report's nodes with the intervals the
    refreshed histories give before anything is shown.

    Args:
        ctx: The shared CLI context.
        report: The report to emit.
        json_output: When ``True``, emit a single JSON document on
            STDOUT; otherwise render the ``rich`` table on STDOUT via
            ``ctx.out``.
        detail: The ``--detail`` level; ``full`` refreshes and adds health.

    Returns:
        The report as emitted (re-judged after a refresh), whose exit
        code counts.
    """
    health = (
        assess_status(report, detail.refresher, client=detail.client)
        if detail.refresher is not None and detail.client is not None
        else None
    )
    if health is not None:
        nodes = tuple(health.nodes[node.node_id].node for node in report.nodes)
        report = dataclasses.replace(report, nodes=nodes)
    elif not json_output and detail.stale_refresher is not None:
        outcome = refresh_status_histories(report, detail.stale_refresher)
        nodes = rejudged_nodes(
            report.nodes, outcome.histories, now=time.time(), floor=report.thresholds
        )
        report = dataclasses.replace(report, nodes=nodes)
    if json_output:
        click.echo(
            health_render.status_json(report, health)
            if health is not None
            else render.render_json(report)
        )
    else:
        render.render_console(
            report,
            console=ctx.out,
            brief=detail.level == DETAIL_BRIEF,
            extra=health_render.status_columns(health) if health is not None else None,
            trends=load_trends(ctx.settings.cache_dir, report.nodes),
            hidden=render.DEFAULT_HIDDEN_COLUMNS if detail.level == DETAIL_DEFAULT else frozenset(),
        )
    return report


def _run_once(ctx: CliContext, options: StatusOptions, client: CachedHTTPClient) -> StatusReport:
    """Run one status collection through an already-open, shared HTTP client.

    Args:
        ctx: The shared CLI context (supplies ``ctx.settings``).
        options: The options shaping this run.
        client: An already-open cache-backed HTTP client, reused across
            polls so ``--watch`` performs at most one network call per
            cache-TTL window.

    Returns:
        The assembled, read-only :class:`~meshprovision.status.report.StatusReport`.
    """
    return run_status(ctx.settings, options, client=client)


def _watch_loop(
    ctx: CliContext,
    options: StatusOptions,
    client: CachedHTTPClient,
    *,
    poll: float,
    json_output: bool,
    fail_on_offline: bool,
    detail: _Detail,
) -> NoReturn:
    """Re-run and re-emit the status report every ``poll`` seconds until Ctrl-C.

    ``options.force_refresh`` (``--no-cache``) applies to the first
    successful poll only; later polls honour the cache TTL like a plain
    ``--watch``.

    Args:
        ctx: The shared CLI context.
        options: The options shaping each run.
        client: The already-open HTTP client shared by every poll.
        poll: Seconds to sleep between polls.
        json_output: Emit JSON instead of the table.
        fail_on_offline: Count offline nodes toward the exit code.
        detail: The ``--detail`` level, shared by every poll.

    Raises:
        DbError: After too many consecutive failed polls.
        SystemExit: On Ctrl-C, with the last report's exit code.
    """
    last_report: StatusReport | None = None
    last_db_error: DbError | None = None
    consecutive_db_failures = 0
    try:
        while True:
            try:
                last_report = _run_once(ctx, options, client)
            except DbError as exc:
                last_db_error = exc
                consecutive_db_failures += 1
                ctx.error(
                    f"Poll failed: {exc.user_message} "
                    f"(keeping the last report; retrying in {poll}s)"
                )
                if consecutive_db_failures >= _WATCH_MAX_CONSECUTIVE_DB_FAILURES:
                    raise
                time.sleep(poll)
                continue
            consecutive_db_failures = 0
            last_db_error = None
            if options.force_refresh:
                # The cache now holds this poll's own data. Bypassing it on
                # every poll would re-query lorastats once per node each
                # --interval, the request pattern lorastats bans IPs for.
                options = dataclasses.replace(options, force_refresh=False)
            last_report = _emit(ctx, last_report, json_output=json_output, detail=detail)
            ctx.info(
                f"cache: {last_report.cache_hits} hit(s), {last_report.cache_misses} "
                f"miss(es), {last_report.network_requests} request(s)"
            )
            time.sleep(poll)
    except KeyboardInterrupt:
        ctx.info("Stopped.")
        if last_db_error is not None:
            code = exit_code_for(last_db_error)
        else:
            code = (
                last_report.exit_code(fail_on_offline=fail_on_offline)
                if last_report is not None
                else int(ExitCode.OK)
            )
        raise SystemExit(code) from None


@click.command(name="status", cls=MeshCommand, context_settings=CONTEXT_SETTINGS)
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of a table."
)
@click.option(
    "--watch", is_flag=True, default=False, help="Poll repeatedly instead of running once."
)
@click.option(
    "--interval",
    type=click.FloatRange(min=1.0, max=_MAX_WATCH_POLL_SECONDS),
    default=None,
    callback=finite_float_callback,
    help=(
        "Poll interval, in seconds (--watch only). Defaults to the cache TTL "
        "(at least 5 s, at most one week)."
    ),
)
@click.option(
    "--node",
    "nodes",
    multiple=True,
    callback=node_ids_callback,
    metavar="ID",
    help="Report on this node only (repeatable).",
)
@click.option(
    "--source",
    "sources",
    multiple=True,
    type=click.Choice([SOURCE_LORANET, SOURCE_LORASTATS]),
    help="Restrict to this data source (repeatable).",
)
@click.option(
    "--region",
    "regions",
    multiple=True,
    metavar="REGION",
    help="lorastats region to query (repeatable; overrides MESHPROVISION_LORASTATS_REGIONS).",
)
@click.option(
    "--refresh-regions",
    is_flag=True,
    default=False,
    help=(
        "Read the lorastats region list from lorastats.pl again now, instead of "
        "the cached one (only when no region is configured)."
    ),
)
@click.option(
    "--stale-after",
    type=click.FloatRange(min=0.0, min_open=True, max=_MAX_THRESHOLD_HOURS),
    default=None,
    callback=finite_float_callback,
    metavar="HOURS",
    help=(
        "Hours a node is online for at least (default 2); its expected interval can make it longer."
    ),
)
@click.option(
    "--offline-after",
    type=click.FloatRange(min=0.0, min_open=True, max=_MAX_THRESHOLD_HOURS),
    default=None,
    callback=finite_float_callback,
    metavar="HOURS",
    help=(
        "Hours before a node can be offline, at least (default 24); its expected "
        "interval can make it longer."
    ),
)
@expected_interval_option(
    help_text=(
        "Expect every reported node every HOURS (at most 48) instead of learning it "
        "from its history, the template or its role; 0.5 gives the fixed thresholds."
    )
)
@click.option(
    "--detail",
    type=click.Choice(DETAIL_LEVELS),
    default=DETAIL_DEFAULT,
    show_default=True,
    help=(
        "Table columns: brief = the essentials; full = also each node's health from "
        "lorastats packet reports (refreshes its 30-day history, see mesh health)."
    ),
)
@click.option(
    "--history-refresh/--no-history-refresh",
    default=True,
    help=(
        "Whether the table refreshes a node's health history from lorastats when it is "
        "over an hour old, for the trend arrows (two requests per node)."
    ),
)
@click.option(
    "--fail-on-offline/--no-fail-on-offline",
    default=True,
    help="Whether an offline node makes the exit code non-zero.",
)
@pass_cli
@handle_cli_errors
def status(
    ctx: CliContext,
    *,
    json_output: bool,
    watch: bool,
    interval: float | None,
    nodes: tuple[NodeId, ...],
    sources: tuple[str, ...],
    regions: tuple[str, ...],
    refresh_regions: bool,
    stale_after: float | None,
    offline_after: float | None,
    expected_interval: float | None,
    detail: str,
    history_refresh: bool,
    fail_on_offline: bool,
) -> None:
    """Report read-only network health for the configured mesh.

    Queries loranet.pl and lorastats.pl (through the shared HTTP cache)
    and merges the results with each node's database record. Never writes
    to the database or to any device.

    Args:
        ctx: The shared CLI context, injected by :data:`~meshprovision.
            cli.common.pass_cli`.
        json_output: Whether to emit JSON, from ``--json``.
        watch: Whether to poll repeatedly, from ``--watch``.
        interval: Poll interval override, from ``--interval``.
        nodes: Node ids to restrict the report to, from ``--node``.
        sources: Data sources to restrict the report to, from
            ``--source``.
        regions: lorastats regions to query, from ``--region``.
        refresh_regions: Whether to read lorastats.pl's region list again,
            from ``--refresh-regions``.
        stale_after: Stale-after threshold override, in hours, from
            ``--stale-after``.
        offline_after: Offline-after threshold override, in hours, from
            ``--offline-after``.
        expected_interval: Every node's expected interval, in hours, from
            ``--expected-interval``.
        detail: The table's columns, from ``--detail``.
        history_refresh: Whether stale histories are refreshed for the trend
            arrows, from ``--history-refresh``/``--no-history-refresh``.
        fail_on_offline: Whether an offline node degrades the exit code,
            from ``--fail-on-offline``/``--no-fail-on-offline``.

    Raises:
        SettingsError: If the resolved thresholds are not strictly
            ordered.
        MissingContactError: If ``MESHPROVISION_CONTACT`` is unset and
            lorastats is one of the resolved sources.
        meshprovision.errors.DbError: If the database cannot be loaded.
            The single-shot path (no ``--watch``) raises this immediately
            and strictly. ``--watch`` instead tolerates it per poll,
            keeping the last successfully-loaded report on screen and
            retrying, and only re-raises (still via this path) after
            :data:`_WATCH_MAX_CONSECUTIVE_DB_FAILURES` consecutive
            failures.
        SystemExit: With the degraded exit code, when the run (or the
            last poll, for ``--watch``) is degraded.
    """
    interval_of_template, preset_of_template = template_hints(ctx.read_template_quietly())
    options = _build_options(
        nodes=nodes,
        sources=sources,
        regions=regions,
        configured_regions=ctx.settings.lorastats_regions,
        refresh_regions=refresh_regions,
        stale_after=stale_after,
        offline_after=offline_after,
        force_refresh=ctx.force_refresh,
        expected_interval=expected_interval,
        template_interval=interval_of_template,
        template_preset=preset_of_template,
    )

    with ctx.http_client(require_contact=SOURCE_LORASTATS in options.sources) as client:
        shown = _Detail(level=detail)
        if detail == DETAIL_FULL:
            store = HistoryStore(ctx.settings.cache_dir / HISTORY_DIRNAME)
            refresher = HealthRefresher(store, LorastatsPackets(client))
            shown = _Detail(level=detail, refresher=refresher, client=client)
        elif history_refresh and SOURCE_LORASTATS in options.sources and not json_output:
            store = HistoryStore(ctx.settings.cache_dir / HISTORY_DIRNAME)
            stale = HealthRefresher(
                store, LorastatsPackets(client), interval=STATUS_REFRESH_INTERVAL_SECONDS
            )
            shown = _Detail(level=detail, client=client, stale_refresher=stale)
        if not watch:
            report = _emit(
                ctx, _run_once(ctx, options, client), json_output=json_output, detail=shown
            )
            code = report.exit_code(fail_on_offline=fail_on_offline)
            if code:
                raise SystemExit(code)
            return

        poll = (
            interval
            if interval is not None
            else min(max(ctx.settings.cache_ttl, _MIN_WATCH_POLL_SECONDS), _MAX_WATCH_POLL_SECONDS)
        )
        _watch_loop(
            ctx,
            options,
            client,
            poll=poll,
            json_output=json_output,
            fail_on_offline=fail_on_offline,
            detail=shown,
        )
