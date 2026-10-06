"""The ODS write gate: whether, and how, an apply outcome updates the database.

:func:`persist_result` is the single gate that decides whether the
``Nodes``/``Keys`` sheets may be updated after
:func:`meshprovision.provisioning.apply.apply_plan` -- it refuses outright
when any write is left in an uncertain state, and turns a failed save
into an :class:`~meshprovision.errors.AtomicWriteError` that says the
device and the database now disagree.

Split out of :mod:`meshprovision.provisioning.apply`, which imports
:func:`persist_result` and re-exports it in its own ``__all__``
unchanged, so a caller may still import it from there. This module never
talks to a device: it imports nothing from ``meshtastic``,
:mod:`~meshprovision.provisioning.connection`,
:mod:`~meshprovision.provisioning.detect`, or :mod:`meshprovision.cli`.

Secret hygiene: nothing here ever logs or renders key material; the
keypair is only handed to :meth:`~meshprovision.db.keys.KeyRecord.for_keypair`.
"""

from __future__ import annotations

import logging
from datetime import datetime

from meshprovision.crypto.keys import KeyPair
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRepository
from meshprovision.db.schema import KeyOrigin
from meshprovision.errors import AtomicWriteError, DbConcurrentModificationError
from meshprovision.provisioning.apply_session import ApplyOutcome

__all__ = ["persist_result"]

_logger = logging.getLogger(__name__)


def persist_result(
    outcome: ApplyOutcome,
    *,
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair | None = None,
    origin: KeyOrigin,
    now: datetime | None = None,
) -> bool:
    """The single gate deciding whether an apply outcome may update the ODS.

    Args:
        outcome: The result of
            :func:`~meshprovision.provisioning.apply.apply_plan`.
        nodes: The node repository to upsert into.
        keys: The key repository to upsert into. Must share the same
            :class:`~meshprovision.db.ods.OdsDatabase` session as
            ``nodes`` -- this is what makes the final :meth:`save` atomic
            across both sheets.
        keypair: The freshly generated keypair, when one was confirmed on
            the device (``key_plan.regenerate``); or the device's own
            already-existing keypair, when the plan adopted it instead of
            overwriting it (``key_plan.adopt_device_key``, firmware issue
            #7449). Either way, ``keys`` is updated to match what the
            device now holds.
        origin: How ``keypair``'s material came to be recorded -- computed
            by the caller (see ``cli/provision_keys.py``'s ``_node_key_origin``).
            Required even when ``keypair`` is ``None`` (unused in that
            case), so every caller is forced to compute it rather than
            accidentally defaulting.
        now: Timestamp to record. Defaults to the current time.

    Returns:
        ``True`` if the database was updated and saved; ``False`` if the
        outcome was in an uncertain state and nothing was written. The
        two failure modes are deliberately different shapes: an uncertain
        outcome is a *refusal* the caller renders (see
        ``cli/provision.py``'s "UNCERTAIN state" message), while a failed
        save is an *error*, because by then the device has already
        changed and the database has not.

    Raises:
        AtomicWriteError: If saving the database fails after the device
            write was already confirmed. Raised in place of the
            underlying filesystem error -- including a bare ``OSError``
            from serializing into the temp file, which ``atomic_write``
            does not itself wrap -- so the operator is told that the
            device and the database now disagree for this node, rather
            than only that a file could not be written.
    """
    if not outcome.may_update_database or outcome.record is None:
        _logger.warning(
            "Skipping database update for %s: node is in an uncertain state",
            outcome.node_id.display,
        )
        return False

    if keypair is not None:
        public_record, private_record = KeyRecord.for_keypair(
            outcome.record.node_id, keypair, origin=origin, created_ts=now
        )
        keys.upsert(public_record)
        keys.upsert(private_record)

    # Captured before the upsert below, which would otherwise always find
    # a row (the one it is about to write) -- this is what lets the
    # save-failure hint tell a first provision/bootstrap (no prior row)
    # apart from an already-provisioned node's key change.
    had_row = nodes.find(outcome.record.node_id) is not None
    nodes.upsert(outcome.record, now=now)
    try:
        nodes.db.save()
    except (AtomicWriteError, OSError) as exc:
        if isinstance(exc, DbConcurrentModificationError):
            opening = (
                "The database file changed on disk since mesh read it (close/save it in "
                "LibreOffice first)"
            )
        else:
            opening = "Fix the write problem (free space, permissions)"
        hint = (
            f"{opening} and re-run "
            "`mesh provision` for this node: the next run re-reads the device's "
            "live configuration and rewrites the row. Because that row was never "
            "saved, a node `mesh adopt` first recorded is still marked observed -- "
            "pass --enroll again on the re-run."
        )
        if keypair is not None and had_row:
            hint = (
                f"{hint} This run also generated a new node keypair that was never "
                "recorded; the next `mesh provision` re-reads the device's key and "
                "records it (it will be reported as differing from the Keys sheet -- "
                "expected here)."
            )
        elif keypair is not None:
            hint = (
                f"{hint} This run also generated a new node keypair that was never "
                "recorded, and a later run will not adopt a device key the database "
                "has never seen -- pass --force-regenerate-key on the re-run to put "
                "a recorded key back on the device."
            )
        raise AtomicWriteError(
            f"Node {outcome.node_id.display} was written and verified on the "
            f"device, but the database could not be saved ({exc}); the device and "
            "the database now disagree for this node.",
            path=str(nodes.db.path),
            hint=hint,
        ) from exc
    return True
