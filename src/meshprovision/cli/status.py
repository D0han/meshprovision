"""``mesh status`` -- strictly read-only network health reporting.

This module MUST NOT reference ``OdsDatabase``, ``NodeRepository``,
``KeyRepository``, ``atomic_writer``, ``meshprovision.provisioning.apply``,
``meshprovision.provisioning.repair``,
:meth:`meshprovision.cli.common.CliContext.open_database`, or any
``save``/``replace``/``upsert``/``delete`` name. Everything flows through
:func:`meshprovision.status.report.run_status`, which is itself certified
read-only (an e2e test asserts the ODS file's mtime is unchanged across a
full ``mesh status`` run). This module docstring restates that guarantee
so a future reader does not have to rediscover it.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import click

from meshprovision.cli.common import CONTEXT_SETTINGS, handle_cli_errors, pass_cli
from meshprovision.datasources.base import SOURCE_LORANET, SOURCE_LORASTATS
from meshprovision.datasources.lorastats import DEFAULT_REGIONS
from meshprovision.errors import ExitCode, SettingsError
from meshprovision.nodeid import NodeId
from meshprovision.status import render
from meshprovision.status.merge import (
    DEFAULT_OFFLINE_AFTER,
    DEFAULT_STALE_AFTER,
    SOURCE_PRIORITY,
    Thresholds,
)
from meshprovision.status.report import StatusOptions, StatusReport, run_status

if TYPE_CHECKING:
    from meshprovision.cache.http import CachedHTTPClient
    from meshprovision.cli.common import CliContext

__all__ = ["status"]

_MIN_WATCH_POLL_SECONDS = 5.0
"""Floor applied to the default watch-poll interval when no ``--interval`` is given."""


def _build_options(
    *,
    nodes: tuple[str, ...],
    sources: tuple[str, ...],
    regions: tuple[str, ...],
    stale_after: float | None,
    offline_after: float | None,
    fail_on_offline: bool,
    force_refresh: bool,
) -> StatusOptions:
    """Build a validated :class:`StatusOptions` from raw CLI values.

    Args:
        nodes: Node id strings from ``--node`` (any accepted
            :class:`~meshprovision.nodeid.NodeId` form). Empty means every
            node in the database.
        sources: Data source names from ``--source``. Empty means every
            configured source.
        regions: lorastats region codes from ``--region``. Empty means
            :data:`~meshprovision.datasources.lorastats.DEFAULT_REGIONS`.
        stale_after: Hours from ``--stale-after``, or ``None`` for the
            default.
        offline_after: Hours from ``--offline-after``, or ``None`` for the
            default.
        fail_on_offline: Whether an offline node degrades the exit code,
            from ``--fail-on-offline``/``--no-fail-on-offline``.
        force_refresh: Whether to bypass the HTTP cache read, from the
            global ``--no-cache``/``--force-refresh``.

    Returns:
        The validated :class:`~meshprovision.status.report.StatusOptions`.

    Raises:
        SettingsError: If the resolved thresholds are not strictly
            ordered (``stale_after < offline_after``).
        NodeIdError: If any value in ``nodes`` cannot be parsed as a node
            id.
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

    node_ids = tuple(NodeId.parse(value) for value in nodes)

    return StatusOptions(
        thresholds=thresholds,
        force_refresh=force_refresh,
        sources=tuple(sources) or SOURCE_PRIORITY,
        regions=tuple(regions) or DEFAULT_REGIONS,
        node_ids=node_ids,
        fail_on_offline=fail_on_offline,
    )


def _emit(ctx: CliContext, report: StatusReport, *, json_output: bool) -> None:
    """Emit one status report to the appropriate stream.

    Args:
        ctx: The shared CLI context.
        report: The report to emit.
        json_output: When ``True``, emit a single JSON document on
            STDOUT; otherwise render the ``rich`` table on STDOUT via
            ``ctx.out``.
    """
    if json_output:
        click.echo(render.render_json(report))
    else:
        render.render_console(report, console=ctx.out)


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


@click.command(name="status", context_settings=CONTEXT_SETTINGS)
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of a table."
)
@click.option(
    "--watch", is_flag=True, default=False, help="Poll repeatedly instead of running once."
)
@click.option(
    "--interval",
    type=click.FloatRange(min=1.0),
    default=None,
    help="Poll interval, in seconds (--watch only). Defaults to the cache TTL.",
)
@click.option(
    "--node", "nodes", multiple=True, metavar="ID", help="Report on this node only (repeatable)."
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
    help="lorastats region to query (repeatable).",
)
@click.option(
    "--stale-after",
    type=click.FloatRange(min=0.0, min_open=True),
    default=None,
    metavar="HOURS",
    help="Hours before a node stops being considered online.",
)
@click.option(
    "--offline-after",
    type=click.FloatRange(min=0.0, min_open=True),
    default=None,
    metavar="HOURS",
    help="Hours before a node is considered offline.",
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
    nodes: tuple[str, ...],
    sources: tuple[str, ...],
    regions: tuple[str, ...],
    stale_after: float | None,
    offline_after: float | None,
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
        stale_after: Stale-after threshold override, in hours, from
            ``--stale-after``.
        offline_after: Offline-after threshold override, in hours, from
            ``--offline-after``.
        fail_on_offline: Whether an offline node degrades the exit code,
            from ``--fail-on-offline``/``--no-fail-on-offline``.

    Raises:
        SettingsError: If the resolved thresholds are not strictly
            ordered.
        MissingContactError: If ``MESHPROVISION_CONTACT`` is unset and
            lorastats is one of the resolved sources.
        SystemExit: With the degraded exit code, when the run (or the
            last poll, for ``--watch``) is degraded.
    """
    options = _build_options(
        nodes=nodes,
        sources=sources,
        regions=regions,
        stale_after=stale_after,
        offline_after=offline_after,
        fail_on_offline=fail_on_offline,
        force_refresh=ctx.force_refresh,
    )

    with ctx.http_client(require_contact=SOURCE_LORASTATS in options.sources) as client:
        if not watch:
            report = _run_once(ctx, options, client)
            _emit(ctx, report, json_output=json_output)
            code = report.exit_code(fail_on_offline=fail_on_offline)
            if code:
                raise SystemExit(code)
            return

        poll = (
            interval
            if interval is not None
            else max(ctx.settings.cache_ttl, _MIN_WATCH_POLL_SECONDS)
        )
        last_report: StatusReport | None = None
        try:
            while True:
                last_report = _run_once(ctx, options, client)
                _emit(ctx, last_report, json_output=json_output)
                ctx.info(
                    f"cache: {last_report.cache_hits} hit(s), {last_report.cache_misses} "
                    f"miss(es), {last_report.network_requests} request(s)"
                )
                time.sleep(poll)
        except KeyboardInterrupt:
            ctx.info("Stopped.")
            code = (
                last_report.exit_code(fail_on_offline=fail_on_offline)
                if last_report is not None
                else int(ExitCode.OK)
            )
            raise SystemExit(code) from None
