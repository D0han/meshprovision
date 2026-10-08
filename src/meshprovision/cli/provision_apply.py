"""Apply a built plan to the device and persist the outcome, for ``mesh provision``.

Split out of :mod:`meshprovision.cli.provision` for size, with no change in
behavior: :class:`ProvisionOptions` (the operator's flags, shared with
``mesh admin bootstrap``), :func:`apply_and_persist` (apply, report, persist,
and the write-ahead pending-keypair bookkeeping around them) and
:func:`record_proven_private_key`. :mod:`meshprovision.cli.provision`
re-exports :class:`ProvisionOptions` unchanged and calls the rest; nothing here
imports from it, or from any other command module.

Secret hygiene: as in :mod:`meshprovision.cli.provision`, nothing here ever
prints/logs a BLE PIN, a base64 key, or raw key bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from meshprovision.cli.provision_keys import (
    capture_proven_private_key,
    node_key_origin,
    register_admin_alias,
)
from meshprovision.crypto import keys as crypto_keys
from meshprovision.db import pending_keys
from meshprovision.errors import AtomicWriteError
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import apply, detect
from meshprovision.provisioning import plan as plan_mod
from meshprovision.provisioning.persist import save_failure_opening

if TYPE_CHECKING:
    from meshprovision.cli.common import CliContext, DbSession
    from meshprovision.crypto.redact import SecretBytes

__all__ = [
    "ProvisionOptions",
    "apply_and_persist",
    "record_proven_private_key",
]


@dataclass(frozen=True, slots=True)
class ProvisionOptions:
    """Operator-supplied provisioning flags shared by ``provision`` and ``admin bootstrap``.

    Attributes:
        dry_run: Whether to print the plan without touching the device or
            the database, from ``--dry-run``.
        allow_lockdown: Whether ``security.is_managed`` may be enabled,
            from ``--allow-lockdown``.
        allow_weak_admin_key: Whether admin keys that fail the weak-key
            audit may still be authorized, from
            ``--allow-weak-admin-key``.
        force_regenerate_key: Whether to regenerate the node keypair
            unconditionally, from ``--force-regenerate-key``.
        rename: Whether an already-provisioned node may be renamed, from
            ``--rename``.
        no_reconnect: Whether to verify writes against the in-memory
            interface only (a weaker guarantee), from ``--no-reconnect``.
        json_output: Whether to emit machine-readable JSON instead of
            human text, from ``--json``.
        admin_ref: Set only by ``mesh admin bootstrap``: the reference to
            additionally file this node's keys under.
        enroll: Whether to bring an observed node under template
            management, from --enroll.
    """

    dry_run: bool = False
    allow_lockdown: bool = False
    allow_weak_admin_key: bool = False
    force_regenerate_key: bool = False
    rename: bool = False
    no_reconnect: bool = False
    json_output: bool = False
    admin_ref: str | None = None
    enroll: bool = False


def record_proven_private_key(
    ctx: CliContext,
    db: DbSession,
    *,
    node_id: NodeId,
    live_private_key: SecretBytes | None,
    now: datetime,
) -> None:
    """Capture a device-proven private key after a successful persist, and save it.

    Runs only once :func:`~meshprovision.provisioning.persist.persist_result`
    has saved the node's row, so its own save is a second, separate one:
    each "Recorded ..." line is printed only after that save succeeds.

    Args:
        ctx: The shared CLI context.
        db: The already-open database session, already saved once.
        node_id: The node just provisioned.
        live_private_key: The device's live-reported private key, or
            ``None``.
        now: Timestamp to record on any row written.

    Raises:
        AtomicWriteError: If that second save fails (exit code 4), in place
            of the underlying error -- including a
            :class:`~meshprovision.errors.DbConcurrentModificationError`
            and a bare ``OSError`` from serializing -- saying that the
            node's row is saved and only the private key is missing.
    """
    recorded = capture_proven_private_key(
        db, node_id=node_id, live_private_key=live_private_key, now=now
    )
    if not recorded:
        return
    try:
        db.db.save()
    except (AtomicWriteError, OSError) as exc:
        raise AtomicWriteError(
            f"Node {node_id.display} was provisioned and its database row saved, but "
            f"saving the device's proven private key failed ({exc}); the Keys sheet still "
            "has no private key for it.",
            path=str(db.path),
            hint=(
                f"{save_failure_opening(exc)} and re-run `mesh provision` for this node: "
                "it re-checks the device's key and records the private key then. The "
                "device needs no changes."
            ),
        ) from exc
    for line in recorded:
        ctx.info(line)


def apply_and_persist(
    ctx: CliContext,
    db: DbSession,
    session: apply.DeviceSession,
    *,
    change_plan: plan_mod.ChangePlan,
    keypair: crypto_keys.KeyPair | None,
    live: detect.LiveConfig,
    opts: ProvisionOptions,
    pending_keypair_recovered: bool = False,
) -> tuple[apply.ApplyOutcome, bool]:
    """Apply a change plan to the device and persist the result to the database.

    Args:
        ctx: The shared CLI context.
        db: The already-open database session.
        session: The already-open device session.
        change_plan: The plan to apply.
        keypair: The keypair selected by :func:`select_keypair`.
        live: The device's live-read configuration, consulted by
            :func:`record_proven_private_key` for the device's live
            private key -- read before this apply, but unchanged by it
            whenever ``keypair`` is ``None``, the case that matters.
        opts: The operator's provisioning flags.
        pending_keypair_recovered: Whether this run is recovering a
            pending keypair from an earlier interrupted regenerate (see
            :mod:`meshprovision.db.pending_keys`), fed through from
            :func:`run_provision`'s
            :attr:`~meshprovision.provisioning.plan_types.PlanInputs.pending_keypair_recovered`.

    Returns:
        The apply outcome, and whether the database was updated.
    """
    # A write-ahead pending-keypair file was written for this node (by
    # run_provision, before any device write) exactly when this run
    # generates a fresh keypair -- never for adopt_device_key/no-op key
    # plans, and never for a pending-keypair recovery itself (that run
    # reuses an *existing* pending file rather than writing a new one).
    wrote_pending = keypair is not None and change_plan.key_plan.regenerate
    pending_path = pending_keys.pending_key_path(db.path, change_plan.node_id)

    try:
        outcome = apply.apply_plan(
            change_plan,
            session,
            keypair=keypair,
            dry_run=False,
            on_reconnect=lambda: ctx.info(
                "Waiting for the device to reboot; do not unplug or swap it..."
            ),
        )
        for line in outcome.describe():
            ctx.info(line)
        if outcome.public_key_fingerprint is not None:
            ctx.info(f"Device public key: {outcome.public_key_fingerprint}")

        node_origin = node_key_origin(
            change_plan.key_plan, pending_recovered=pending_keypair_recovered
        )

        if (
            opts.admin_ref is not None
            and opts.admin_ref != change_plan.node_id.hex
            and outcome.may_update_database
        ):
            register_admin_alias(
                ctx,
                db,
                admin_ref=opts.admin_ref,
                node_id=change_plan.node_id,
                keypair=keypair,
                node_origin=node_origin,
            )

        now = datetime.now(tz=UTC)
        persisted = apply.persist_result(
            outcome,
            nodes=db.nodes,
            keys=db.keys,
            keypair=keypair,
            origin=node_origin,
            now=now,
        )
    except BaseException:
        # The outcome is unknown here (Ctrl-C, or any other exception --
        # including persist_result's own AtomicWriteError, raised after the
        # device write was already confirmed): keep the pending file and
        # tell the operator it is there, unconditionally.
        if wrote_pending:
            ctx.error(
                f"The new keypair was saved to {pending_path} before the device write; "
                "the next `mesh provision` of this node recovers it automatically."
            )
        raise

    if persisted:
        ctx.success(f"Database updated: {db.path}")
        # The database and the device are now known to agree: any pending
        # keypair recorded for this node -- from this run or an earlier
        # interrupted one -- is provably no longer needed.
        pending_keys.clear_pending(db.path, change_plan.node_id)
        record_proven_private_key(
            ctx,
            db,
            node_id=change_plan.node_id,
            live_private_key=live.security.private_key,
            now=now,
        )
    else:
        if change_plan.key_plan.regenerate and not outcome.security_attempted:
            # Hygiene: the freshly generated key never reached the device
            # (the run stopped before the security section was even
            # attempted), so the pending file describes a key that was
            # never sent -- nothing to recover from it.
            pending_keys.clear_pending(db.path, change_plan.node_id)
        ctx.error("Node is in an UNCERTAIN state; the database was NOT updated.")
        for failure in outcome.failures():
            label = f"{failure.section}.{failure.field}" if failure.field else failure.section
            line = f"{label}: {failure.status.value}"
            if failure.message:
                line = f"{line} -- {failure.message}"
            ctx.error(line)

        if any(
            failure.message.startswith("reconnected to a different node")
            for failure in outcome.failures()
        ):
            ctx.error(
                "Stopped: the device that answered after the reboot is not "
                f"{change_plan.node_id.display}. Check which device is connected before "
                "re-running; nothing further was written to the other device."
            )

        not_written = [r.section for r in outcome.results if r.status is apply.WriteStatus.SKIPPED]
        if not_written:
            ctx.error(f"Not written (stopped after the failure above): {', '.join(not_written)}")
        security_change = next((c for c in change_plan.sections if c.section == "security"), None)
        sets_is_managed = security_change is not None and any(
            fc.field == "is_managed" and fc.desired is True for fc in security_change.changes
        )
        if (
            sets_is_managed
            and outcome.security_attempted
            and not any(
                r.section == "security"
                and r.field == "is_managed"
                and r.status is apply.WriteStatus.CONFIRMED
                for r in outcome.results
            )
        ):
            # E.g. an in-place run whose settings-transaction commit failed:
            # security was sent but never read back.
            ctx.error(
                "The security section was sent but not confirmed: is_managed may have been "
                "applied, so the node may now be locked to its admin keys."
            )
        if "security" in not_written:
            if sets_is_managed:
                ctx.info(
                    "The security section was not written: the node was not locked, "
                    "and its keys and admin keys are unchanged."
                )
            else:
                ctx.info(
                    "The security section was not written: its keys and admin keys are unchanged."
                )

        if wrote_pending:
            if outcome.security_attempted:
                ctx.error(
                    f"The new keypair was saved to {pending_path} before the device write; "
                    "the next `mesh provision` of this node recovers it automatically."
                )
            else:
                ctx.error("The new keypair was never sent to the device; nothing to recover.")

    return outcome, persisted
