"""``mesh remote`` -- offline preflight estimates for reading a node over the mesh.

This version has **no live remote read and no remote write**. ``mesh remote diff`` runs only
with ``--dry-run``; without it, it stops with :class:`~meshprovision.errors.SettingsError`
(exit code 2) before reading anything.

With it, the command reads three things and nothing else:

- the template;
- the database, through ``CliContext.open_database()`` with no keywords. That is a load only,
  never a save; like every command that opens the database, it refreshes the known-good copy
  beside it;
- the destination's health history, through
  :meth:`~meshprovision.health.store.HistoryStore.load`, never ``update``.

No radio, serial, Bluetooth, TCP or HTTP connection is opened. Everything else is pure, in
:mod:`meshprovision.remote`.

This module MUST NOT reference ``transport_options``, ``connected_with_progress``,
``resolve_backend``, ``select_backend``, ``close_interface``, ``http_client``, ``for_write``,
``must_exist``, ``save``, ``upsert``, ``delete``, ``replace``, ``update``, ``lock``,
``write_json`` or any device API. ``tests/unit/test_readonly_remote_boundary.py`` holds it to
that, and ``tests/unit/test_import_contracts.py`` holds it to importing no transport,
connection, provisioning, HTTP or database-write module.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Final

import click

from meshprovision.cli.common import (
    CONTEXT_SETTINGS,
    echo_json,
    handle_cli_errors,
    node_id_callback,
    pass_cli,
)
from meshprovision.cli.help_format import MeshCommand, MeshGroup
from meshprovision.db.schema import ManagementMode
from meshprovision.errors import ExitCode, SettingsError
from meshprovision.health.store import HISTORY_DIRNAME, HistoryStore
from meshprovision.remote.plan import (
    SECTION_CHOICES,
    plan_dry_run,
    template_sections,
)
from meshprovision.remote.plan_types import (
    AirUtilReading,
    Destination,
    DryRunInputs,
    Gateway,
)
from meshprovision.remote.render import plan_to_json, render_text

if TYPE_CHECKING:
    from collections.abc import Mapping

    from meshprovision.cli.common import CliContext
    from meshprovision.config.template import TemplateConfig
    from meshprovision.db.nodes import NodeRecord
    from meshprovision.health.history import NodeHistory
    from meshprovision.nodeid import NodeId

__all__ = ["remote"]

LIVE_READ_UNAVAILABLE: Final[str] = (
    "mesh remote diff has no live mode in this version: it never contacts a radio and "
    "sends nothing."
)


@click.group(name="remote", cls=MeshGroup, context_settings=CONTEXT_SETTINGS)
def remote() -> None:
    """Offline preflight estimates for reading a node over the mesh (sends nothing).

    This version of mesh has no live remote read and no remote write. Its one
    command, `mesh remote diff --dry-run`, works out from the template, the
    database and the local health history alone what a read-only diff of one
    node through the mesh would cost the relays on the way, and whether this
    version's offline rules would allow it.
    """


@remote.command(name="diff", cls=MeshCommand, context_settings=CONTEXT_SETTINGS)
@click.argument("node", callback=node_id_callback, metavar="NODE")
@click.option(
    "--dry-run",
    "dry_run",
    is_flag=True,
    default=False,
    help="Required: estimate only. Nothing is sent; there is no live mode.",
)
@click.option(
    "--gateway",
    callback=node_id_callback,
    default=None,
    metavar="NODE",
    help=(
        "The database node whose radio would send the requests: checks that NODE's "
        "recorded admin keys include its key. Nothing connects to it."
    ),
)
@click.option(
    "--section",
    "sections",
    multiple=True,
    type=click.Choice(SECTION_CHOICES),
    help=(
        "Plan only this section (repeatable); required on LONG_MODERATE and LONG_SLOW. "
        "Default: every section the template sets."
    ),
)
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of text."
)
@pass_cli
@handle_cli_errors
def diff(
    ctx: CliContext,
    *,
    node: NodeId,
    dry_run: bool,
    gateway: NodeId | None,
    sections: tuple[str, ...],
    json_output: bool,
) -> None:
    """Estimate what reading NODE over the mesh would cost; nothing is sent.

    A read is not free: every request and reply is sent again by each relay
    that hears it with hops left (on a first contact, every rebroadcasting
    node within the hop limit, not only the path), and spends that relay's
    legal airtime (10 % of each hour on EU_868). The relays are often other
    people's nodes. This command refuses a plan whose cost to one relay, at
    contention window 7, is over a polite share of 36 s per rolling hour (a
    policy of this tool, not a legal limit), and shows the cost at window 8
    (strong links, SNR 10 to 15 dB) as the worst case. It refuses a full diff
    on LONG_MODERATE and LONG_SLOW (use --section) and never plans to read
    security below firmware 2.8 (the
    reply would carry the node's private key). The gateway's key is what the
    node trusts: whoever holds that radio can administer every node that
    lists it.

    The figures are a planning estimate from simulator-calibrated
    arithmetic, not a measurement. Exit code 5 when a rule refuses the read.

    Args:
        ctx: The shared CLI context.
        node: The node to plan for.
        dry_run: Estimate only, from --dry-run; required.
        gateway: The gateway's database node, from --gateway.
        sections: The sections to plan, from --section; empty plans every
            section the template sets.
        json_output: Emit JSON, from --json.

    Raises:
        SettingsError: Without --dry-run (exit code 2), before anything is read.
        SystemExit: With exit code 5 when an offline rule refuses the read.
    """
    if not dry_run:
        raise SettingsError(
            LIVE_READ_UNAVAILABLE,
            hint=(
                f"Add --dry-run for the offline estimate: `mesh remote diff --dry-run {node.hex}`."
            ),
        )
    template = ctx.load_template()
    with ctx.open_database() as db:
        dest_record = db.nodes.find(node)
        gateway_record = None if gateway is None else db.nodes.find(gateway)
        public_keys = db.keys.public_key_map()
    history = HistoryStore(ctx.settings.cache_dir / HISTORY_DIRNAME).load(node)
    reading = _air_util_tx(history, now=time.time())
    plan = plan_dry_run(
        _inputs(
            template, node, dest_record, gateway, gateway_record, public_keys, reading, sections
        )
    )
    if json_output:
        echo_json(plan_to_json(plan))
    else:
        ctx.print_out(render_text(plan))
    if plan.refusals:
        raise SystemExit(int(ExitCode.PROVISIONING))


def _air_util_tx(history: NodeHistory, *, now: float) -> AirUtilReading | None:
    """Return the newest telemetry point with an ``air_util_tx``; its age is clamped at 0."""
    for point in reversed(history.telemetry):
        if point.air_util_tx is not None:
            return AirUtilReading(point.air_util_tx, max(0.0, now - point.time))
    return None


def _destination(
    node: NodeId,
    record: NodeRecord | None,
    public_keys: Mapping[str, bytes],
    reading: AirUtilReading | None,
) -> Destination:
    if record is None:
        return Destination(label=node.display, found=False)
    return Destination(
        label=node.display,
        found=True,
        archived=record.is_archived,
        template_managed=record.management is ManagementMode.TEMPLATE,
        firmware=record.firmware_version,
        authorized_keys=frozenset(
            public_keys[ref] for ref in record.authorized_admin_keys if ref in public_keys
        ),
        air_util_tx=reading,
    )


def _gateway(node: NodeId, record: NodeRecord | None, public_keys: Mapping[str, bytes]) -> Gateway:
    if record is None:
        return Gateway(label=node.display, found=False)
    return Gateway(
        label=node.display,
        found=True,
        archived=record.is_archived,
        firmware=record.firmware_version,
        public_key=public_keys.get(record.public_key_ref),
    )


def _inputs(
    template: TemplateConfig,
    node: NodeId,
    dest_record: NodeRecord | None,
    gateway: NodeId | None,
    gateway_record: NodeRecord | None,
    public_keys: Mapping[str, bytes],
    reading: AirUtilReading | None,
    sections: tuple[str, ...],
) -> DryRunInputs:
    dumps = {
        name: model.model_dump(exclude_none=True)
        for name, model in (
            ("device", template.device),
            ("position", template.position),
            ("power", template.power),
            ("lora", template.lora),
            ("default_channel", template.default_channel),
            ("security", template.security),
            ("telemetry", template.telemetry),
            ("neighbor_info", template.neighbor_info),
        )
    }
    return DryRunInputs(
        destination=_destination(node, dest_record, public_keys, reading),
        gateway=None if gateway is None else _gateway(gateway, gateway_record, public_keys),
        region=template.lora.region,
        preset=template.lora.modem_preset if template.lora.use_preset else None,
        hop_limit=template.lora.hop_limit,
        override_duty_cycle=template.lora.override_duty_cycle,
        template_sections=template_sections(
            dumps, template.option_state(), has_admin_nodes=bool(template.admin_nodes)
        ),
        requested_sections=frozenset(sections),
    )
