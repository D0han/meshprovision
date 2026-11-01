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
from typing import TYPE_CHECKING, TypeVar

import click

from meshprovision.cli.common import CONTEXT_SETTINGS, handle_cli_errors, pass_cli
from meshprovision.cli.help_format import MeshCommand, MeshGroup
from meshprovision.errors import SettingsError
from meshprovision.network import render
from meshprovision.network.report import (
    DEFAULT_KEYS_DAYS,
    MAX_DAYS,
    NetworkOptions,
    NetworkReport,
    run_network,
)

if TYPE_CHECKING:
    from meshprovision.cli.common import CliContext

__all__ = ["network"]

_F = TypeVar("_F", bound=Callable[..., object])


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
) -> NetworkReport:
    """Run the data side of a view.

    Raises:
        SettingsError: If ``--refresh`` is given with ``--no-fetch``.
    """
    if refresh and no_fetch:
        raise SettingsError("--refresh has no effect with --no-fetch.", hint="Drop one of the two.")
    options = NetworkOptions(
        days=days, regions=regions, fetch=not no_fetch, refresh=refresh, traffic=traffic
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
