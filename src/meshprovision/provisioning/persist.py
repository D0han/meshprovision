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
from meshprovision.db.schema import KeyOrigin, KeyType, ManagementMode, ref_for
from meshprovision.errors import AtomicWriteError, DbConcurrentModificationError
from meshprovision.provisioning.apply_session import ApplyOutcome

__all__ = ["persist_result", "save_failure_opening"]

_logger = logging.getLogger(__name__)


def save_failure_opening(exc: BaseException) -> str:
    """The first clause of a database-save-failure hint: what to fix before re-running.

    Shared by every hint that follows a failed save of the database, so
    the concurrent-edit advice reads the same everywhere.

    Args:
        exc: The exception the failed save raised.

    Returns:
        The LibreOffice advice for a
        :class:`~meshprovision.errors.DbConcurrentModificationError`;
        otherwise the generic write-problem advice. Either one reads as
        the start of a sentence continued with " and re-run ...".
    """
    if isinstance(exc, DbConcurrentModificationError):
        return (
            "The database file changed on disk since mesh read it (close/save it in "
            "LibreOffice first)"
        )
    return "Fix the write problem (free space, permissions)"


def _unrecorded_keypair_hint(origin: KeyOrigin, *, had_row: bool, had_key: bool) -> str:
    """Say how the next run records a keypair that a failed save left unrecorded.

    Args:
        origin: :attr:`~meshprovision.db.schema.KeyOrigin.GENERATED`
            exactly when the node's pending-keypair file holds the key --
            written ahead by this run's regenerate, or the one this run
            recovered from -- since a failed save never clears it (see
            ``cli/provision_apply.py``'s ``apply_and_persist``). Otherwise the
            key is the device's own, adopted or captured.
        had_row: Whether the node had a ``Nodes`` row before this run.
            Without one, the re-run sees a FOREIGN node and asks for
            confirmation again.
        had_key: Whether the ``Keys`` sheet held the node's public key
            before this run. With one, a re-run that adopts the device's
            key reports it as differing (firmware issue #7449).

    Returns:
        The hint's keypair sentences, without a leading space.
    """
    if origin is KeyOrigin.GENERATED:
        text = (
            "The node's new keypair was not recorded either, but it is still in this "
            "node's pending-keypair file: the next `mesh provision` recovers it "
            "automatically, without writing a new key to the device."
        )
        if had_key:
            text = (
                f"{text} If that file is lost, the next run instead reports the device's "
                "key as differing from the Keys sheet and adopts it -- expected here."
            )
        else:
            text = (
                f"{text} If that file is lost, the next run instead records the device's "
                "current key as captured."
            )
    elif had_key:
        text = (
            "The device's keypair was not recorded either; the next `mesh provision` "
            "reports it as differing from the Keys sheet again and adopts it -- "
            "expected here."
        )
    else:
        text = (
            "The device's own keypair was not recorded either; the next "
            "`mesh provision` captures it again."
        )
    if had_row:
        return text
    return (
        f"{text} That run sees the node as FOREIGN (not in the database) and asks for "
        "confirmation: answer yes, or pass --yes on a non-interactive run."
    )


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
            by the caller (see ``cli/provision_keys.py``'s ``node_key_origin``).
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
            than only that a file could not be written. Its hint says how
            the re-run records what was lost: by the node's own history
            before this run (no row, an observed row, a recorded public
            key) and by ``origin`` (a pending-keypair file to recover from,
            or the device's own key to adopt again).
    """
    if not outcome.may_update_database or outcome.record is None:
        _logger.warning(
            "Skipping database update for %s: node is in an uncertain state",
            outcome.node_id.display,
        )
        return False

    # Both read before this function's own upserts, which would otherwise
    # always find the row and the key it is about to write -- this is what
    # lets the save-failure hint tell a first provision (no row, no key)
    # apart from an already-recorded node, and an observed (`mesh adopt`)
    # row, which the re-run must --enroll again, from a managed one.
    prior = nodes.find(outcome.record.node_id)
    had_key = keys.find(ref_for(outcome.record.node_id, KeyType.ADMIN_PUBLIC)) is not None
    if keypair is not None:
        public_record, private_record = KeyRecord.for_keypair(
            outcome.record.node_id, keypair, origin=origin, created_ts=now
        )
        keys.upsert(public_record)
        keys.upsert(private_record)

    nodes.upsert(outcome.record, now=now)
    try:
        nodes.db.save()
    except (AtomicWriteError, OSError) as exc:
        hint = (
            f"{save_failure_opening(exc)} and re-run `mesh provision` for this node: "
            "the next run re-reads the device's live configuration and rewrites the row."
        )
        if prior is not None and prior.management is ManagementMode.OBSERVED:
            hint = (
                f"{hint} Because that row was never saved, the node is still marked "
                "observed -- pass --enroll again on the re-run."
            )
        if keypair is not None:
            keypair_hint = _unrecorded_keypair_hint(
                origin, had_row=prior is not None, had_key=had_key
            )
            hint = f"{hint} {keypair_hint}"
        raise AtomicWriteError(
            f"Node {outcome.node_id.display} was written and verified on the "
            f"device, but the database could not be saved ({exc}); the device and "
            "the database now disagree for this node.",
            path=str(nodes.db.path),
            hint=hint,
        ) from exc
    return True
