"""``mesh health`` -- per-node health and importance, strictly read-only.

Like ``mesh status`` (see :mod:`meshprovision.cli.status`), this module
MUST NOT reference ``OdsDatabase``, ``NodeRepository``, ``KeyRepository``,
``atomic_writer``, ``known_good``, ``pending_keys``,
:meth:`meshprovision.cli.common.CliContext.open_database`, or any
``save``/``replace``/``upsert``/``delete`` name; everything flows through
:func:`meshprovision.health.report.run_health`, which never writes the
database. Besides the HTTP cache and the lorastats region list and memo,
the only files it writes are the per-node health histories in the cache
directory.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import click

from meshprovision.cli.common import (
    CONTEXT_SETTINGS,
    handle_cli_errors,
    node_ids_callback,
    pass_cli,
)
from meshprovision.cli.help_format import MeshCommand
from meshprovision.datasources.lorastats_regions import RegionList
from meshprovision.errors import SettingsError
from meshprovision.health import render
from meshprovision.health.report import DEFAULT_DAYS, MAX_DAYS, HealthOptions, run_health

if TYPE_CHECKING:
    from meshprovision.cli.common import CliContext
    from meshprovision.nodeid import NodeId

__all__ = ["health"]


@click.command(name="health", cls=MeshCommand, context_settings=CONTEXT_SETTINGS)
@click.argument("nodes", nargs=-1, callback=node_ids_callback, metavar="[NODE]...")
@click.option(
    "--days",
    type=click.IntRange(1, MAX_DAYS),
    default=DEFAULT_DAYS,
    show_default=True,
    help="Window of the local history to judge, in days.",
)
@click.option(
    "--no-fetch",
    "no_fetch",
    is_flag=True,
    default=False,
    help="Ask nothing: use the local history and the database only.",
)
@click.option(
    "--refresh",
    is_flag=True,
    default=False,
    help=(
        "Refresh the history even if it was refreshed in the last 10 minutes "
        "(still at most once a minute per node)."
    ),
)
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of text."
)
@pass_cli
@handle_cli_errors
def health(
    ctx: CliContext,
    *,
    nodes: tuple[NodeId, ...],
    days: int,
    no_fetch: bool,
    refresh: bool,
    json_output: bool,
) -> None:
    """Judge each node's health and importance from lorastats packet reports.

    Without NODE: every active node of the database, one row each. With
    NODE (one or more): those nodes in detail, including a check of what
    each uplinked as an MQTT gateway. Keeps a 30-day history per node in
    the cache directory. Never writes to the database or to any device.

    Args:
        ctx: The shared CLI context.
        nodes: Node ids to report on in detail; empty means every active node.
        days: The window, from ``--days``.
        no_fetch: Ask nothing, from ``--no-fetch``.
        refresh: Refresh within the 10-minute interval, from ``--refresh``.
        json_output: Emit JSON, from ``--json``.

    Raises:
        SettingsError: If ``--refresh`` is given with ``--no-fetch``.
        SystemExit: With exit code 7 when a node is critical or a source
            or refresh failed.
    """
    if refresh and no_fetch:
        raise SettingsError("--refresh has no effect with --no-fetch.", hint="Drop one of the two.")
    regions = ctx.settings.lorastats_regions or ()
    options = HealthOptions(
        days=days,
        fetch=not no_fetch,
        refresh=refresh,
        gateway_checks=bool(nodes),
        node_ids=tuple(dict.fromkeys(nodes)),
        regions=regions,
        region_list=None if regions else RegionList(),
        force_refresh=ctx.force_refresh,
    )
    with ctx.http_client(require_contact=not no_fetch) as client:
        report = run_health(ctx.settings, options, client=client)
    if json_output:
        click.echo(render.render_json(report))
    else:
        render.render_console(report, console=ctx.out, detail=bool(nodes))
    code = report.exit_code()
    if code:
        raise SystemExit(code)
