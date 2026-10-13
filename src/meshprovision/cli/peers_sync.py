"""Run the peers sync against one open device session, for ``mesh peers`` and ``mesh provision``.

Reads the connected device's NodeDB and the database's fleet, plans which
contacts and favorites are missing (:mod:`meshprovision.provisioning.peers`),
and, when asked, writes them and reads the result back. It never writes the
database: peers are derived from it, not recorded in it.

Split from :mod:`meshprovision.cli.peers` (the ``mesh peers`` command) so
:mod:`meshprovision.cli.provision` can run the same step without importing
another command module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from meshprovision.errors import ExitCode, MeshprovisionError
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import connection, detect, peers
from meshprovision.provisioning.device_write import DEVICE_EXCEPTIONS

if TYPE_CHECKING:
    from meshprovision.cli.common import CliContext, DbSession
    from meshprovision.provisioning.apply import DeviceSession

__all__ = [
    "PeersReport",
    "run_peers",
    "sync_peers_after_provision",
]


@dataclass(frozen=True, slots=True)
class PeersReport:
    """The result of one peers run.

    Attributes:
        own_node: The connected device's id.
        plan: What was missing when the run started.
        applied: Whether writes were attempted (``--apply``).
        outcome: What the device accepted, or ``None`` for a dry run or an
            empty plan.
        remaining: Nodes still missing contact or favorite after the
            read-back; always empty for a dry run.
    """

    own_node: NodeId
    plan: peers.PeersPlan
    applied: bool
    outcome: peers.PeersOutcome | None = None
    remaining: tuple[NodeId, ...] = ()

    @property
    def exit_code(self) -> int:
        """The process exit code for this run.

        Returns:
            ``OK`` unless a write raised or did not survive the read-back,
            then ``PROVISIONING``. A dry run with work pending is ``OK``:
            it only reports.
        """
        failed = self.outcome is not None and not self.outcome.ok
        return int(ExitCode.PROVISIONING if failed or self.remaining else ExitCode.OK)


def _plan(
    db: DbSession, session: DeviceSession, *, known_bad: frozenset[bytes]
) -> tuple[NodeId, peers.PeersPlan, dict[NodeId, str]]:
    """Plan the sync against the session's current interface.

    Args:
        db: The open database session.
        session: The open device session.
        known_bad: The known-bad-keys blocklist for the weak-key audit.

    Returns:
        The device's own id, the plan, and why each weak-keyed node's key
        was refused (``{node: reason}``).
    """
    iface = session.interface
    own = detect.read_node_id(iface)
    nodes = db.nodes.all()
    public_keys = peers.public_key_map(db.keys, nodes)
    contacts = peers.screen_contacts(
        peers.build_contacts(nodes, public_keys), public_keys, known_bad=known_bad
    )
    reasons = {c.node_id: c.weak_reason for c in contacts if c.weak_reason}
    return own, peers.plan_peers(own, contacts, peers.read_live_peers(iface)), reasons


def _remaining_after(
    db: DbSession, session: DeviceSession, *, known_bad: frozenset[bytes]
) -> tuple[NodeId, ...]:
    """Re-read the device after the writes and list what is still missing.

    Args:
        db: The open database session.
        session: The open device session.
        known_bad: The blocklist the first plan was screened with.

    Returns:
        The nodes the device still lacks as contact or favorite; empty
        when the session cannot read back (an in-place session has no
        independent view of the device).
    """
    if not session.reads_back:
        return ()
    session.refresh()
    _, replan, _ = _plan(db, session, known_bad=known_bad)
    return tuple(action.contact.node_id for action in replan.actions)


def run_peers(
    ctx: CliContext, db: DbSession, session: DeviceSession, *, apply: bool
) -> PeersReport:
    """Plan the peers sync and, with ``apply``, perform and verify it.

    Args:
        ctx: The shared CLI context, used for progress output.
        db: The open database session (read only here).
        session: The open device session.
        apply: Whether to write. ``False`` only reports the plan.

    Returns:
        The report. Every problem that needs attention is also printed
        through ``ctx``.
    """
    known_bad = ctx.known_bad_keys()
    own, plan, weak_reasons = _plan(db, session, known_bad=known_bad)
    for node_id in plan.weak_key:
        ctx.warn(
            f"{node_id.display}: its recorded public key failed the weak-key audit "
            f"({weak_reasons[node_id]}); not added or favorited. Run `mesh db verify`, "
            "then re-key the node (`mesh provision --force-regenerate-key`)."
        )
    for node_id in plan.key_mismatch:
        ctx.warn(
            f"{node_id.display}: the device holds a different public key than the database; "
            "left alone. Verify which is right (`mesh adopt` re-reads the device)."
        )
    if plan.no_key:
        names = ", ".join(node_id.display for node_id in plan.no_key)
        ctx.warn(f"No public key recorded for {names}: they cannot be added as contacts.")
    for action in plan.actions:
        steps = [
            s
            for s, on in (("add contact", action.add_contact), ("favorite", action.favorite))
            if on
        ]
        ctx.info(f"{action.contact.node_id.display}: {' + '.join(steps)}")
    if plan.is_empty:
        attention = len(plan.weak_key) + len(plan.key_mismatch) + len(plan.no_key)
        if attention:
            ctx.info(f"Nothing to write; {attention} node(s) left as reported above.")
        else:
            ctx.success("Peers are in sync: nothing to change.")
        return PeersReport(own_node=own, plan=plan, applied=apply)
    if not apply:
        ctx.info(f"{len(plan.actions)} node(s) need changes; re-run with --apply to write them.")
        return PeersReport(own_node=own, plan=plan, applied=False)

    outcome = peers.apply_peers(session.interface.localNode, plan)
    for node_id, message in outcome.failures:
        ctx.error(f"{node_id.display}: {message}")
    remaining = _remaining_after(db, session, known_bad=known_bad)
    if remaining:
        names = ", ".join(node_id.display for node_id in remaining)
        ctx.error(f"Sent, but the device does not show {names} after reconnecting.")
    elif outcome.ok:
        ctx.success(f"Peers synced: {len(plan.actions)} node(s) updated.")
    return PeersReport(own_node=own, plan=plan, applied=True, outcome=outcome, remaining=remaining)


def sync_peers_after_provision(ctx: CliContext, db: DbSession, session: DeviceSession) -> None:
    """Run the sync as the optional last step of ``mesh provision``.

    Never fatal: the node is already provisioned and recorded, so any
    failure here is a warning to re-run ``mesh peers --apply``.

    Args:
        ctx: The shared CLI context.
        db: The open database session.
        session: The open device session, already past its provisioning
            reconnect.
    """
    ctx.info("Syncing peer contacts and favorites (template: sync_peers)...")
    caught: tuple[type[BaseException], ...] = (
        MeshprovisionError,
        *DEVICE_EXCEPTIONS,
        *connection.device_io_errors(),
    )
    try:
        report = run_peers(ctx, db, session, apply=True)
    except caught as exc:
        ctx.warn(
            f"Peer sync failed ({exc}); the node itself is provisioned. Run `mesh peers --apply`."
        )
        return
    if report.exit_code:
        ctx.warn("Peer sync incomplete; run `mesh peers --apply` to retry.")
