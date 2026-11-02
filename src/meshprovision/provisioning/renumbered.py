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
instead.

One renumber cannot be followed: firmware 2.8 creates a node's first key,
and so changes its id, the moment a LoRa region is first set, without a
reboot and in the middle of a run's writes (verified in firmware source;
what the rest of the run's admin messages then do is not).
:func:`region_first_refusal` refuses such a plan before anything is
written. Nothing here writes anything.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from meshprovision.crypto.keys import public_key_matches
from meshprovision.db.pending_keys import find_pending_holding
from meshprovision.db.schema import KeyType, is_canonical_node_owner
from meshprovision.errors import NodeRenumberedError, PlanConflictError
from meshprovision.firmware import derives_node_id_from_key
from meshprovision.nodeid import NodeId, key_derived_id

if TYPE_CHECKING:
    from pathlib import Path

    from meshprovision.db.keys import KeyRepository
    from meshprovision.db.node_record import NodeRecord
    from meshprovision.db.nodes import NodeRepository
    from meshprovision.db.pending_keys import PendingKeypair
    from meshprovision.provisioning.detect_types import LiveConfig
    from meshprovision.provisioning.plan_types import ChangePlan

__all__ = [
    "PENDING_KEY_EVIDENCE",
    "SAME_KEY_EVIDENCE",
    "UNSET_REGION",
    "refuse_renumbered",
    "refuse_renumbered_pending",
    "region_first_refusal",
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


UNSET_REGION: Final[str] = "UNSET"
"""The LoRa region a factory-fresh device reports before one is set."""


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


def region_first_refusal(plan: ChangePlan, live: LiveConfig) -> PlanConflictError | None:
    """Refuse a plan that sets a firmware 2.8 device's LoRa region for the first time.

    Firmware 2.8 holds back key generation while the region is unset and
    creates the key, renumbering the node, as soon as one is first set
    (``AdminModule`` -> ``ensurePkiIdentity``): the rest of this run's
    writes would go to an id the device no longer has. An empty or
    unparseable firmware version is treated as older firmware. A device
    that already holds a key and the id derived from it keeps both (see
    :func:`_keeps_its_id`), and is not refused.

    Args:
        plan: The plan about to be applied.
        live: The device's live configuration the plan was built from.

    Returns:
        The refusal when the plan writes ``lora.region``, the device
        reports :data:`UNSET_REGION`, its firmware is >= 2.8 and it would
        not keep its id; else ``None``.
    """
    lora = plan.section("lora")
    change = next((c for c in lora.changes if c.field == "region"), None) if lora else None
    if (
        change is None
        or str(live.value("lora", "region")) != UNSET_REGION
        or not derives_node_id_from_key(live.firmware_version)
        or _keeps_its_id(plan, live)
    ):
        return None
    return PlanConflictError(
        f"{live.node_id.display} has no LoRa region yet, and firmware >= 2.8 creates its key "
        "and changes its node id the moment a region is first set: the rest of this run's "
        "writes would go to an id the device no longer has.",
        field="lora.region",
        hint=(
            "Set the LoRa region first (Meshtastic app, or "
            f"`meshtastic --set lora.region {change.desired}`), reconnect, then run "
            "`mesh provision` again."
        ),
    )


def _keeps_its_id(plan: ChangePlan, live: LiveConfig) -> bool:
    """Tell whether a first region leaves a firmware 2.8 device's key, and so its id, alone.

    An unlicensed device holding a private key only re-derives its public
    key from it when the region is first set (``CryptoEngine::ensurePkiKeys``)
    and keeps its id when that is already the key's derived one
    (``NodeDB::createNewIdentity``); both verified in the firmware source
    at 2.8.0 and 2.8.1. A licensed device takes another path and is never
    trusted to, nor is a plan that writes a new key in the same run.
    """
    public, private = live.security.real_public_key, live.security.real_private_key
    return (
        not live.is_licensed
        and not plan.key_plan.regenerate
        and public is not None
        and private is not None
        and key_derived_id(public) == live.node_id
        and public_key_matches(private, public)
    )


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
