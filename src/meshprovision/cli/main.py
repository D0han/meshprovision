"""The ``mesh`` console script's top-level click group.

Defines the ``cli`` group object that ``pyproject.toml``'s
``[project.scripts]`` entry (``mesh = "meshprovision.cli.main:cli"``)
invokes directly -- there is deliberately no separate ``main()``
wrapper. Declares every global option, builds the layered
:class:`~meshprovision.cli.common.Settings` and the shared
:class:`~meshprovision.cli.common.CliContext`, and registers the seven
subcommands produced by the cli-commands group: ``provision``,
``status``, ``admin``, ``db``, ``adopt``, ``template``, ``init``.

The group callback does no I/O beyond building settings and configuring
logging on a help-only invocation -- ``mesh --help`` and ``mesh <cmd>
--help`` (at any nesting depth) stay instant and side-effect free. On an
*interactive* run of an actual command, it additionally offers to create
whatever first-run artifacts (``.env``, the template, the database) are
still missing, via :func:`~meshprovision.cli.init_cmd.maybe_offer_setup`
-- see that module for the wizard itself.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import click

from meshprovision import __version__
from meshprovision.cli.admin import admin
from meshprovision.cli.adopt import adopt
from meshprovision.cli.common import (
    CONTEXT_SETTINGS,
    LOG_LEVELS,
    CliContext,
    MeshGroup,
    build_settings,
    configure_logging,
    handle_cli_errors,
    resolve_log_level,
    resolve_non_interactive,
)
from meshprovision.cli.db_cmd import db
from meshprovision.cli.init_cmd import init, maybe_offer_setup
from meshprovision.cli.provision import provision
from meshprovision.cli.status import status
from meshprovision.cli.template_cmd import template

__all__ = ["cli"]

_LOG_LEVEL_CHOICES: Final[tuple[str, ...]] = tuple(level.lower() for level in LOG_LEVELS)
"""Lower-cased log-level choices: ``case_sensitive=False`` returns the
lowercase form actually passed to ``click.Choice``, so the choices
themselves are declared lowercase to match."""


@click.group(name="mesh", cls=MeshGroup, context_settings=CONTEXT_SETTINGS)
@click.version_option(version=__version__, prog_name="mesh", message="%(prog)s %(version)s")
@click.option(
    "--log-level",
    type=click.Choice(_LOG_LEVEL_CHOICES, case_sensitive=False),
    default=None,
    help="Logging verbosity (default: MESHPROVISION_LOG_LEVEL, else WARNING).",
)
@click.option(
    "-v",
    "--verbose",
    count=True,
    help=(
        "Increase log detail; repeatable. -v: this tool's own logs (INFO). "
        "-vv: DEBUG, plus meshtastic/httpx. -vvv: also bleak/httpcore/urllib3. "
        "Overridden by an explicit --log-level."
    ),
)
@click.option(
    "--db-path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Override the ODS node database path.",
)
@click.option(
    "--template-path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Override the provisioning template path.",
)
@click.option(
    "--cache-ttl",
    type=click.FloatRange(min=0.0),
    default=None,
    help="HTTP response cache time-to-live, in seconds.",
)
@click.option(
    "--no-cache",
    is_flag=True,
    default=False,
    help="Bypass cache reads; responses are still written back to the cache.",
)
@click.option(
    "--force-refresh",
    is_flag=True,
    default=False,
    help="Alias for --no-cache.",
)
@click.option(
    "--non-interactive/--interactive",
    "non_interactive",
    default=None,
    help="Turn every prompt into an error. Auto-enabled when stdin is not a TTY.",
)
@click.option(
    "--env-file",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Explicit .env file to read instead of searching upward from the CWD.",
)
@click.pass_context
@handle_cli_errors
def cli(
    ctx: click.Context,
    *,
    log_level: str | None,
    verbose: int,
    db_path: Path | None,
    template_path: Path | None,
    cache_ttl: float | None,
    no_cache: bool,
    force_refresh: bool,
    non_interactive: bool | None,
    env_file: Path | None,
) -> None:
    """Provision and monitor Meshtastic mesh nodes on the PL mesh.

    Run interactively with setup incomplete, it offers to create
    whatever's missing (``.env``, the template, the database) before the
    command you asked for gets a chance to fail. Run ``mesh init``
    directly to do the same thing on your own terms.

    Args:
        ctx: The click context. ``ctx.obj`` is set to the shared
            :class:`~meshprovision.cli.common.CliContext` every
            subcommand receives via :data:`~meshprovision.cli.common.
            pass_cli`.
        log_level: Logging verbosity override, from ``--log-level``.
            Wins over ``verbose`` when both are given -- see
            :func:`~meshprovision.cli.common.resolve_log_level`.
        verbose: The ``-v``/``--verbose`` count. With no explicit
            ``--log-level``, a count of 1 raises this project's own
            loggers to ``INFO``, 2 or 3 to ``DEBUG``; a count of 2 or 3
            additionally unmutes third-party loggers -- see
            :func:`~meshprovision.cli.common.configure_logging`.
        db_path: ODS database path override, from ``--db-path``.
        template_path: Provisioning template path override, from
            ``--template-path``.
        cache_ttl: HTTP cache TTL override, from ``--cache-ttl``.
        no_cache: Whether to bypass cache reads, from ``--no-cache``.
        force_refresh: Alias for ``no_cache``, from ``--force-refresh``.
        non_interactive: Whether every prompt should error instead of
            prompting, from ``--non-interactive``/``--interactive``.
            ``None`` auto-resolves from whether stdin is a TTY.
        env_file: Explicit ``.env`` file to read, from ``--env-file``.

    Raises:
        SettingsError: If the layered settings fail validation.
    """
    settings = build_settings(
        env_file=env_file,
        db_path=db_path,
        template_path=template_path,
        cache_ttl=cache_ttl,
        log_level=resolve_log_level(log_level, verbose),
    )
    configure_logging(settings.log_level, verbosity=verbose)
    cli_ctx = CliContext.build(
        settings=settings,
        non_interactive=resolve_non_interactive(non_interactive),
        force_refresh=no_cache or force_refresh,
        env_file=env_file,
        verbosity=verbose,
    )

    outcome = maybe_offer_setup(cli_ctx, click_ctx=ctx)
    if outcome is not None and outcome.contact is not None:
        # A fresh .env was written and a contact prompted for: layer it
        # onto the live settings rather than re-reading the .env it just
        # wrote, so it takes effect for the rest of this run.
        cli_ctx = cli_ctx.with_settings(settings.with_overrides(contact=outcome.contact))
    ctx.obj = cli_ctx


for command in (provision, status, admin, db, adopt, template, init):
    cli.add_command(command)
