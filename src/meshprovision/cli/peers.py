"""``mesh peers`` -- make the connected device know and favorite the rest of the fleet.

Every active node in the database (except the connected device itself) is
sent to the device as a contact, with the public key the database records,
and marked favorite so the device never evicts it. That matters most for
routers and base stations, which must keep reaching, and holding the keys
of, the whole fleet. Without ``--apply`` the command only reports what is
missing; with it, the writes are read back after a reconnect.

The database is only read. Run it once per device, or set ``sync_peers: true``
in the template so ``mesh provision`` does it as its last step.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import click

from meshprovision.cli.common import (
    CONTEXT_SETTINGS,
    echo_json,
    handle_cli_errors,
    pass_cli,
)
from meshprovision.cli.help_format import MeshCommand
from meshprovision.cli.peers_sync import PeersReport, run_peers
from meshprovision.cli.transport import (
    TransportOptions,
    device_session,
    resolve_backend,
    transport_options,
)
from meshprovision.provisioning import connection

if TYPE_CHECKING:
    from meshprovision.cli.common import CliContext

__all__ = ["peers"]


def _report_json(report: PeersReport) -> dict[str, object]:
    """Render a report for ``--json``.

    Args:
        report: The finished run.

    Returns:
        A JSON-serializable mapping with node ids only (no key material).
    """
    return {
        "node": report.own_node.display,
        "applied": report.applied,
        "to_change": [
            {
                "node": action.contact.node_id.display,
                "add_contact": action.add_contact,
                "favorite": action.favorite,
            }
            for action in report.plan.actions
        ],
        "in_sync": [node_id.display for node_id in report.plan.in_sync],
        "no_key": [node_id.display for node_id in report.plan.no_key],
        "key_mismatch": [node_id.display for node_id in report.plan.key_mismatch],
        "weak_key": [node_id.display for node_id in report.plan.weak_key],
        "unfavorite": [node_id.display for node_id in report.plan.unfavorite],
        "failed": (
            [{"node": n.display, "error": m} for n, m in report.outcome.failures]
            if report.outcome is not None
            else []
        ),
        "unconfirmed": [node_id.display for node_id in report.remaining],
    }


@click.command(name="peers", cls=MeshCommand, context_settings=CONTEXT_SETTINGS)
@transport_options
@click.option(
    "--apply",
    "apply_changes",
    is_flag=True,
    default=False,
    help="Write the missing contacts and favorites (default: only report them).",
)
@click.option(
    "--prune-archived",
    is_flag=True,
    default=False,
    help=(
        "Also unfavorite nodes archived in the database (`mesh db forget`) that the device "
        "still has favorited. Never removes them from the device's node list."
    ),
)
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of human text."
)
@pass_cli
@handle_cli_errors
def peers(
    ctx: CliContext,
    *,
    port: str | None,
    ble_address: str | None,
    ble_scan: bool,
    host: str | None,
    interface: str | None,
    timeout: int,
    ble_scan_timeout: float,
    apply_changes: bool,
    prune_archived: bool,
    json_output: bool,
) -> None:
    """Add every fleet node to the connected device's contacts and favorite it.

    Connects over serial, BLE, or TCP, compares the device's NodeDB with
    the database's active nodes, and reports which contacts and favorites
    are missing. A node the device already holds under a different public
    key, or whose recorded key fails the weak-key audit, is reported and
    left alone.

    Args:
        ctx: The shared CLI context, injected by :data:`~meshprovision.
            cli.common.pass_cli`.
        port: Explicit serial port, from ``--port``.
        ble_address: Explicit BLE address, from ``--ble-address``.
        ble_scan: Whether to force BLE and scan, from ``--ble-scan``.
        host: Explicit TCP host, from ``--host``.
        interface: Forced transport name, from ``--interface``.
        timeout: Connect timeout, in seconds, from ``--timeout``.
        ble_scan_timeout: BLE scan duration, from ``--ble-scan-timeout``.
        apply_changes: Whether to write, from ``--apply``.
        prune_archived: Whether to also unfavorite archived nodes, from
            ``--prune-archived``.
        json_output: Whether to emit JSON, from ``--json``.

    Raises:
        SystemExit: With a non-zero code when a write failed or was not
            confirmed by the read-back.
    """
    transport_opts = TransportOptions(
        interface=connection.Transport(interface) if interface is not None else None,
        port=port,
        ble_address=ble_address,
        ble_scan=ble_scan,
        host=host,
        timeout=timeout,
        ble_scan_timeout=ble_scan_timeout,
    )
    with ctx.open_database() as db:
        backend = resolve_backend(ctx, transport_opts)
        with device_session(ctx, backend) as session:
            report = run_peers(ctx, db, session, apply=apply_changes, prune_archived=prune_archived)

    if json_output:
        echo_json(_report_json(report))
    if report.exit_code:
        raise SystemExit(report.exit_code)
