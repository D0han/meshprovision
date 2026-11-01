"""``mesh network`` -- region-wide views from lorastats raw packets, strictly read-only.

Like ``mesh health`` (see :mod:`meshprovision.cli.health`), this module
MUST NOT reference ``OdsDatabase``, ``NodeRepository``, ``KeyRepository``,
``atomic_writer``, ``known_good``, ``pending_keys``,
:meth:`meshprovision.cli.common.CliContext.open_database`, or any
``save``/``replace``/``upsert``/``delete`` name; everything flows through
:func:`meshprovision.network.report.run_network`, which never writes the
database. Besides the HTTP cache, the only files it writes are the region
stores in the cache directory.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Final, TypeVar

import click

from meshprovision.cli.common import (
    CONTEXT_SETTINGS,
    handle_cli_errors,
    node_ids_callback,
    pass_cli,
)
from meshprovision.cli.help_format import MeshCommand, MeshGroup
from meshprovision.errors import SettingsError
from meshprovision.network import render, render_graph, render_impact
from meshprovision.network.report import (
    DEFAULT_KEYS_DAYS,
    DEFAULT_TRAFFIC_DAYS,
    MAX_DAYS,
    NetworkOptions,
    NetworkReport,
    run_network,
)

if TYPE_CHECKING:
    from meshprovision.cli.common import CliContext
    from meshprovision.nodeid import NodeId

__all__ = ["DEFAULT_RELAY_ROWS", "MAX_RELAY_ROWS", "network"]

_F = TypeVar("_F", bound=Callable[..., object])

DEFAULT_RELAY_ROWS: Final[int] = 20
"""Relays shown per region by default."""

MAX_RELAY_ROWS: Final[int] = 255
"""The most relays ``--limit`` allows (there are at most 255 relay bytes)."""


@click.group(name="network", cls=MeshGroup, context_settings=CONTEXT_SETTINGS)
def network() -> None:
    """Region-wide views of the mesh from lorastats raw packets (read-only).

    Each view looks at the lorastats regions our nodes were last found in
    (at most 4; run `mesh status` once to learn them) or the ones given
    with --region, and keeps a 30-day store of each region's traffic in
    the cache directory. Never writes to the database or to any device.
    """


def _common_options(default_days: int) -> Callable[[_F], _F]:
    """Add the options every view shares."""

    def decorate(func: _F) -> _F:
        for option in reversed(
            (
                click.option(
                    "--days",
                    type=click.IntRange(1, MAX_DAYS),
                    default=default_days,
                    show_default=True,
                    help="Window of the stored data to look at, in days.",
                ),
                click.option(
                    "--region",
                    "regions",
                    multiple=True,
                    help="A lorastats region to look at (repeatable); default: our nodes' regions.",
                ),
                click.option(
                    "--no-fetch",
                    "no_fetch",
                    is_flag=True,
                    default=False,
                    help="Ask nothing: use the stored data only.",
                ),
                click.option(
                    "--refresh",
                    is_flag=True,
                    default=False,
                    help=(
                        "Fetch even if fetched in the last 15 minutes "
                        "(still at most once a minute per region)."
                    ),
                ),
                click.option(
                    "--json",
                    "json_output",
                    is_flag=True,
                    default=False,
                    help="Emit JSON instead of text.",
                ),
            )
        ):
            func = option(func)
        return func

    return decorate


def _collect(
    ctx: CliContext,
    *,
    days: int,
    regions: tuple[str, ...],
    no_fetch: bool,
    refresh: bool,
    traffic: bool,
    loranet: bool = False,
    neighbors: bool = False,
) -> NetworkReport:
    """Run the data side of a view.

    Raises:
        SettingsError: If ``--refresh`` is given with ``--no-fetch``.
    """
    if refresh and no_fetch:
        raise SettingsError("--refresh has no effect with --no-fetch.", hint="Drop one of the two.")
    options = NetworkOptions(
        days=days,
        regions=regions,
        fetch=not no_fetch,
        refresh=refresh,
        traffic=traffic,
        loranet=loranet,
        neighbors=neighbors,
    )
    known_bad = ctx.known_bad_keys()
    with ctx.http_client(require_contact=not no_fetch) as client:
        return run_network(ctx.settings, options, client=client, known_bad=known_bad)


@network.command(name="keys", cls=MeshCommand, context_settings=CONTEXT_SETTINGS)
@_common_options(DEFAULT_KEYS_DAYS)
@pass_cli
@handle_cli_errors
def keys(
    ctx: CliContext,
    *,
    days: int,
    regions: tuple[str, ...],
    no_fetch: bool,
    refresh: bool,
    json_output: bool,
) -> None:
    """Scan the public keys every node of the region advertises.

    Finds our keys on other ids, other keys on our ids, weak keys, keys
    shared by several ids (a clone, a hand-over or a firmware 2.8 id
    migration) and keys that changed. Only nodes whose node info travels
    unencrypted can be seen. Keys are kept as 64-bit digests only.

    Args:
        ctx: The shared CLI context.
        days: The window, from ``--days``.
        regions: The regions, from ``--region``.
        no_fetch: Ask nothing, from ``--no-fetch``.
        refresh: Fetch within the 15-minute interval, from ``--refresh``.
        json_output: Emit JSON, from ``--json``.

    Raises:
        SystemExit: 6 when a critical finding involves one of our nodes,
            3 when no region has any data, 7 when a request failed.
    """
    report = _collect(
        ctx, days=days, regions=regions, no_fetch=no_fetch, refresh=refresh, traffic=False
    )
    if json_output:
        click.echo(render.render_keys_json(report))
    else:
        render.render_keys_console(report, console=ctx.out)
    code = report.exit_code(crypto=report.keys_critical)
    if code:
        raise SystemExit(code)


@network.command(name="relays", cls=MeshCommand, context_settings=CONTEXT_SETTINGS)
@_common_options(DEFAULT_TRAFFIC_DAYS)
@click.option(
    "--all",
    "everything",
    is_flag=True,
    default=False,
    help="Every relay of the region by its share of relayed traffic, not only those carrying ours.",
)
@click.option(
    "--limit",
    type=click.IntRange(1, MAX_RELAY_ROWS),
    default=DEFAULT_RELAY_ROWS,
    show_default=True,
    help="The most relays shown per region (--json lists all).",
)
@pass_cli
@handle_cli_errors
def relays(
    ctx: CliContext,
    *,
    days: int,
    regions: tuple[str, ...],
    no_fetch: bool,
    refresh: bool,
    json_output: bool,
    everything: bool,
    limit: int,
) -> None:
    """List the relays that carry our nodes' packets but are not ours.

    Each relay byte is attributed to a node with a confidence label
    (high/medium) or shown as ambiguous with its candidates. For each:
    the share of our relayed receptions it carried, which of our nodes
    use it as their only first hop, its share of the region's relayed
    traffic, the gateways that rely on it, and its health and identity
    gaps, with its device health (battery, voltage, uptime, channel
    utilization) from loranet's node dump. Shares are of receptions at
    gateways, by last hop.

    Args:
        ctx: The shared CLI context.
        days: The window, from ``--days``.
        regions: The regions, from ``--region``.
        no_fetch: Ask nothing, from ``--no-fetch``.
        refresh: Fetch within the 15-minute interval, from ``--refresh``.
        json_output: Emit JSON, from ``--json``.
        everything: Every relay, from ``--all``.
        limit: The most rows per region, from ``--limit``.

    Raises:
        SystemExit: 3 when no region has any data, 7 when a request failed
            (loranet's included).
    """
    report = _collect(
        ctx,
        days=days,
        regions=regions,
        no_fetch=no_fetch,
        refresh=refresh,
        traffic=True,
        loranet=True,
    )
    if json_output:
        click.echo(render.render_relays_json(report, everything=everything))
    else:
        render.render_relays_console(report, console=ctx.out, everything=everything, limit=limit)
    code = report.exit_code()
    if code:
        raise SystemExit(code)


@network.command(name="impact", cls=MeshCommand, context_settings=CONTEXT_SETTINGS)
@click.argument("nodes", nargs=-1, callback=node_ids_callback, metavar="[NODE]...")
@_common_options(DEFAULT_TRAFFIC_DAYS)
@pass_cli
@handle_cli_errors
def impact(
    ctx: CliContext,
    *,
    nodes: tuple[NodeId, ...],
    days: int,
    regions: tuple[str, ...],
    no_fetch: bool,
    refresh: bool,
    json_output: bool,
) -> None:
    """Show what depends on our nodes, or on any NODE.

    Without NODE: how much of the region's relayed traffic our nodes
    carried, how many outside origins and gateways rely on them, and each
    of our nodes' impact level. With NODE (ours or not): that node in
    detail. Shares are of receptions at gateways, by last hop: who carries
    traffic now, not what breaks without it.

    Args:
        ctx: The shared CLI context.
        nodes: Nodes to detail; empty means our nodes' summary.
        days: The window, from ``--days``.
        regions: The regions, from ``--region``.
        no_fetch: Ask nothing, from ``--no-fetch``.
        refresh: Fetch within the 15-minute interval, from ``--refresh``.
        json_output: Emit JSON, from ``--json``.

    Raises:
        SystemExit: 3 when no region has any data, 7 when a request failed.
    """
    report = _collect(
        ctx, days=days, regions=regions, no_fetch=no_fetch, refresh=refresh, traffic=True
    )
    detail = [node.hex for node in dict.fromkeys(nodes)]
    if json_output:
        click.echo(render_impact.render_impact_json(report, nodes=detail))
    else:
        render_impact.render_impact_console(report, console=ctx.out, nodes=detail)
    code = report.exit_code()
    if code:
        raise SystemExit(code)


@network.command(name="graph", cls=MeshCommand, context_settings=CONTEXT_SETTINGS)
@_common_options(DEFAULT_TRAFFIC_DAYS)
@pass_cli
@handle_cli_errors
def graph(
    ctx: CliContext,
    *,
    days: int,
    regions: tuple[str, ...],
    no_fetch: bool,
    refresh: bool,
    json_output: bool,
) -> None:
    """Build a relay graph of the region and look for single points of failure.

    Observed: origins whose only first hop seen was one relay (the strong
    claim). Inferred: nodes whose removal cuts well-observed nodes off from
    MQTT in the graph (the weak claim). Our nodes: vertex-disjoint paths to
    MQTT next to their observed first hops. Prints what the graph does not
    claim; --json includes every edge with its evidence. loranet's
    neighbour lists are added as edges of their own, and only what they
    change in the inferred measures is reported, apart.

    Args:
        ctx: The shared CLI context.
        days: The window, from ``--days``.
        regions: The regions, from ``--region``.
        no_fetch: Ask nothing, from ``--no-fetch``.
        refresh: Fetch within the 15-minute interval, from ``--refresh``.
        json_output: Emit JSON, from ``--json``.

    Raises:
        SystemExit: 3 when no region has any data, 7 when a request failed
            (loranet's included).
    """
    report = _collect(
        ctx,
        days=days,
        regions=regions,
        no_fetch=no_fetch,
        refresh=refresh,
        traffic=True,
        loranet=True,
        neighbors=True,
    )
    if json_output:
        click.echo(render_graph.render_graph_json(report))
    else:
        render_graph.render_graph_console(report, console=ctx.out)
    code = report.exit_code()
    if code:
        raise SystemExit(code)
