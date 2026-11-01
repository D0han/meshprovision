"""Recognise, at connect time, a database node that firmware >= 2.8 renumbered.

Firmware 2.8 derives a node's id from its public key
(:func:`~meshprovision.nodeid.key_derived_id`): a node upgraded from 2.7
renumbers on its first 2.8 boot, and a 2.8 node after a key write. The
device then reports an id the database has no row for, and would look
FOREIGN. Two kinds of evidence say which row it was:

- the device's public key is exactly one live node row's recorded key
  (:func:`renumbered_row`), and the device's id is the one derived from it;
- the device holds, both halves, the pending keypair an interrupted
  ``mesh provision`` wrote to another id (:func:`renumbered_pending`), and
  its id is the one derived from that keypair.

``mesh provision`` and ``mesh adopt`` refuse such a node before writing
anything, naming the ``mesh db renumber`` command that moves the row
(:func:`renumbered_error`); a pending keypair whose id has no live row
(an interrupted factory provisioning) is recovered under the new id
instead. Nothing here writes anything.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from meshprovision.db.pending_keys import find_pending_holding
from meshprovision.db.schema import KeyType, is_canonical_node_owner
from meshprovision.errors import NodeRenumberedError
from meshprovision.nodeid import NodeId, key_derived_id

if TYPE_CHECKING:
    from pathlib import Path

    from meshprovision.db.keys import KeyRepository
    from meshprovision.db.node_record import NodeRecord
    from meshprovision.db.nodes import NodeRepository
    from meshprovision.db.pending_keys import PendingKeypair
    from meshprovision.provisioning.detect_types import LiveConfig

__all__ = [
    "PENDING_KEY_EVIDENCE",
    "SAME_KEY_EVIDENCE",
    "refuse_renumbered",
    "refuse_renumbered_pending",
    "renumber_command",
    "renumbered_error",
    "renumbered_pending",
    "renumbered_row",
]

SAME_KEY_EVIDENCE: Final[str] = "same public key"
"""Why a device is a row's node: it reports that row's recorded public key."""

PENDING_KEY_EVIDENCE: Final[str] = (
    "it holds the keypair an interrupted `mesh provision` wrote to it"
)
"""Why a device is a row's node: it holds that row's pending keypair."""


def renumber_command(old: NodeId, new: NodeId) -> str:
    """Return the command that moves ``old``'s row to ``new``.

    Args:
        old: The id the database knows the node by.
        new: The id the device reports now.

    Returns:
        For example ``"mesh db renumber deadbe01 3a7c19e2"``.
    """
    return f"mesh db renumber {old.hex} {new.hex}"


def renumbered_error(old: NodeId, new: NodeId, *, evidence: str) -> NodeRenumberedError:
    """Build the refusal for a device that is ``old`` now reporting ``new``.

    Args:
        old: The id the database knows the node by.
        new: The id the device reports now.
        evidence: Why the device is ``old`` (:data:`SAME_KEY_EVIDENCE` or
            :data:`PENDING_KEY_EVIDENCE`).

    Returns:
        The error, its hint naming :func:`renumber_command`.
    """
    return NodeRenumberedError(
        f"This is {old.display} ({evidence}) now reporting {new.display}: firmware >= 2.8 "
        "derives the node id from the key.",
        old=old.display,
        new=new.display,
        hint=f"Move its database row to the new id, then re-run: {renumber_command(old, new)}",
    )


def renumbered_row(
    live: LiveConfig, *, nodes: NodeRepository, keys: KeyRepository
) -> NodeRecord | None:
    """Find the row a device reporting an unknown id was, by its public key.

    Args:
        live: The device's live configuration.
        nodes: The node repository.
        keys: The key repository.

    Returns:
        The one live (not archived) node row, other than the device's own
        id, whose recorded public key is exactly the device's, when the
        device's id is the one derived from that key; otherwise ``None``
        (no key, another id, no such row, or a key two node rows hold,
        which the duplicate-key audit reports instead).
    """
    public = live.security.real_public_key
    if public is None or key_derived_id(public) != live.node_id:
        return None
    holders = [
        record.owner_node_id
        for record in keys.of_type(KeyType.ADMIN_PUBLIC)
        if is_canonical_node_owner(record.owner_node_id)
        and record.owner_node_id != live.node_id.hex
        and record.material() == public
    ]
    if len(holders) != 1:
        return None
    record = nodes.find(holders[0])
    if record is None or record.is_archived:
        return None
    return record


def refuse_renumbered(live: LiveConfig, *, nodes: NodeRepository, keys: KeyRepository) -> None:
    """Refuse a device that is a renumbered database node (see :func:`renumbered_row`).

    Call only when the device's id has no row of its own.

    Args:
        live: The device's live configuration.
        nodes: The node repository.
        keys: The key repository.

    Raises:
        NodeRenumberedError: If the device is one.
    """
    record = renumbered_row(live, nodes=nodes, keys=keys)
    if record is not None:
        raise renumbered_error(record.node, live.node_id, evidence=SAME_KEY_EVIDENCE)


def renumbered_pending(
    live: LiveConfig, pending: PendingKeypair | None, *, nodes: NodeRepository
) -> PendingKeypair | None:
    """Decide what a pending keypair the device holds, filed under another id, means.

    Args:
        live: The device's live configuration.
        pending: The pending keypair the device holds exactly, found by
            :func:`~meshprovision.db.pending_keys.find_pending_holding`,
            or ``None``.
        nodes: The node repository.

    Returns:
        ``pending``, to recover under the device's id, when the device's
        id derives from it and its own id has no row (an interrupted
        factory provisioning, or a row already moved); ``None`` when
        there is none, the id does not derive from it, or its id's row is
        archived.

    Raises:
        NodeRenumberedError: If its id has a live row: that row must be
            moved first (``mesh db renumber`` accepts the pending keypair
            as proof).
    """
    if pending is None or key_derived_id(pending.public) != live.node_id:
        return None
    record = nodes.find(pending.node_id)
    if record is None:
        return pending
    if record.is_archived:
        return None
    raise renumbered_error(pending.node_id, live.node_id, evidence=PENDING_KEY_EVIDENCE)


def refuse_renumbered_pending(live: LiveConfig, *, db_path: Path, nodes: NodeRepository) -> None:
    """Refuse a device that holds the pending keypair of a live row and reports its derived id.

    For ``mesh adopt``, which never recovers a pending keypair: a device
    an interrupted ``mesh provision`` renumbered is that row's node, and
    adopting it would record one device under two rows. Call only when the
    device's id has no row of its own.

    Args:
        live: The device's live configuration.
        db_path: The database's path (the pending keypairs sit beside it).
        nodes: The node repository.

    Raises:
        NodeRenumberedError: If the device is one (see :func:`renumbered_pending`).
    """
    public, private = live.security.real_public_key, live.security.real_private_key
    if public is None or private is None:
        return
    renumbered_pending(
        live, find_pending_holding(db_path, public=public, private=private), nodes=nodes
    )
