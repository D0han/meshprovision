"""Move a node's database row to a new node id: the one row-move primitive.

Firmware >= 2.8 derives a node's id from its public key
(:func:`~meshprovision.nodeid.key_derived_id`): a node upgraded from 2.7
renumbers on its first 2.8 boot, and any 2.8 node renumbers after a key
write. Everything this database keys by node id must then follow it.
:func:`renumber_rows` moves, in memory only:

- the ``Nodes`` row, with a note appended to ``notes`` saying which id it
  had until when (see :func:`renumber_note`);
- the node's own ``Keys`` rows (``<id>_pub``, ``<id>_priv``, ``<id>_psk``),
  keeping their material, origin and timestamp;
- every ``authorized_admin_keys`` reference to them, on every row.

:func:`check_renumber` holds the guards ``mesh db renumber`` applies
first. The new id must be the one firmware derives from a key this node
is known to hold, its recorded public key (held by no other node row) or
the pending keypair an interrupted ``mesh provision`` left for it, unless
the operator forces it; whatever is forced, the old row must exist and not
be archived, and the new id must be free (no row, no key rows) and not
reserved.

The pending-keypair file and the region memo live outside the database
and are moved by the caller after the save. The health history cache stays
under the old id.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, NoReturn

from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRepository
from meshprovision.db.schema import KeyType, is_canonical_node_owner, ref_for
from meshprovision.errors import RenumberRefusedError
from meshprovision.nodeid import NodeId, is_reserved_id, key_derived_id

if TYPE_CHECKING:
    from collections.abc import Mapping

    from meshprovision.db.node_record import NodeRecord

__all__ = [
    "NOTE_SEPARATOR",
    "Renumbered",
    "append_note",
    "check_new_id",
    "check_renumber",
    "renumber_note",
    "renumber_rows",
]

NOTE_SEPARATOR: Final[str] = "; "
"""Joins a note appended to a non-empty ``notes`` cell."""

_FORCE_HINT: Final[str] = (
    "Check that the device now reporting {new} really is {old} (the same hardware), "
    "then re-run with --force to move it anyway."
)


@dataclass(frozen=True, slots=True)
class Renumbered:
    """What :func:`renumber_rows` moved.

    Attributes:
        old: The id the row had.
        new: The id it has now.
        keys: The node's ``Keys`` references under the new id, in
            ``KeyType`` order.
        referencing: The other rows whose ``authorized_admin_keys`` were
            rewritten, by hex id (the moved row's own are rewritten as it
            moves).
        note: The note appended to the row's ``notes``.
    """

    old: NodeId
    new: NodeId
    keys: tuple[str, ...]
    referencing: tuple[str, ...]
    note: str


def renumber_note(old: NodeId, *, until: datetime) -> str:
    """Say which id a node had until when, for its ``notes`` cell.

    Args:
        old: The id the node had.
        until: When it stopped having it (the UTC date is used).

    Returns:
        For example ``"node id was !deadbe01 until 2026-11-01 (firmware
        2.8 key-derived id)"``.
    """
    day = until.astimezone(UTC).strftime("%Y-%m-%d")
    return f"node id was {old.display} until {day} (firmware 2.8 key-derived id)"


def append_note(notes: str, note: str) -> str:
    """Append ``note`` to a ``notes`` cell, after :data:`NOTE_SEPARATOR` when not empty.

    Args:
        notes: The cell's current text.
        note: The note to add.

    Returns:
        The new cell text.
    """
    return f"{notes}{NOTE_SEPARATOR}{note}" if notes else note


def _own_refs(node: NodeId) -> tuple[str, ...]:
    """Return a node's own ``Keys`` references, in ``KeyType`` order."""
    return tuple(ref_for(node.hex, key_type) for key_type in KeyType)


def _refuse(message: str, *, old: NodeId, new: NodeId, hint: str | None = None) -> NoReturn:
    """Raise :class:`RenumberRefusedError` for ``old`` -> ``new``."""
    raise RenumberRefusedError(message, old=old.display, new=new.display, hint=hint)


def check_renumber(
    nodes: NodeRepository,
    keys: KeyRepository,
    *,
    old: NodeId,
    new: NodeId,
    pending_public: bytes | None = None,
    new_has_pending: bool = False,
    force: bool = False,
) -> NodeRecord:
    """Check that ``old``'s row may move to ``new``, before anything is changed.

    Args:
        nodes: The node repository.
        keys: The key repository.
        old: The id whose row moves.
        new: The id it moves to.
        pending_public: The public half of the pending keypair an
            interrupted ``mesh provision`` left for ``old``, if any.
        new_has_pending: Whether a pending keypair is already filed under
            ``new`` (a key some device may hold; never overwritten).
        force: Skip the proof that ``new`` derives from a key ``old``
            holds; the other guards still apply.

    Returns:
        ``old``'s row.

    Raises:
        NodeNotFoundError: If ``old`` has no row.
        RenumberRefusedError: If ``new`` is ``old``, reserved, or taken (a
            row, a key row under its references, or a pending keypair); if
            ``old``'s row is archived; or, without ``force``, if ``new`` is not the id
            derived from ``pending_public`` or from ``old``'s recorded
            public key (which no other node row may hold).
    """
    record = nodes.get(old)
    if record.is_archived:
        _refuse(f"Node {old.display} was archived via `mesh db forget`.", old=old, new=new)
    check_new_id(nodes, keys, old=old, new=new)
    if new_has_pending:
        _refuse(
            f"A pending keypair is already filed under {new.display}; it is not overwritten.",
            old=old,
            new=new,
            hint=(
                f"Run `mesh provision` on the device now reporting {new.display} first: it "
                "recovers or clears that keypair."
            ),
        )
    if not force:
        _check_proof(keys, old=old, new=new, pending_public=pending_public)
    return record


def check_new_id(nodes: NodeRepository, keys: KeyRepository, *, old: NodeId, new: NodeId) -> None:
    """Check that ``new`` is free for ``old``'s node: not ``old``, not reserved, unused.

    Args:
        nodes: The node repository.
        keys: The key repository.
        old: The id the node had (need not have a row).
        new: The id it is to have.

    Raises:
        RenumberRefusedError: If ``new`` is ``old``, reserved, has a row,
            or has key rows under its own references.
    """
    if new == old:
        _refuse(f"{old.display} already has that id.", old=old, new=new)
    if is_reserved_id(new):
        _refuse(f"{new.display} is reserved; no node can have it.", old=old, new=new)
    if nodes.find(new) is not None:
        _refuse(f"Node {new.display} already has a row in the database.", old=old, new=new)
    stray = [ref for ref in _own_refs(new) if keys.find(ref) is not None]
    if stray:
        _refuse(
            f"The Keys sheet already has {', '.join(stray)}; {new.display} is not free.",
            old=old,
            new=new,
        )


def _check_proof(
    keys: KeyRepository, *, old: NodeId, new: NodeId, pending_public: bytes | None
) -> None:
    """Refuse unless ``new`` derives from a key ``old`` holds (see :func:`check_renumber`)."""
    if pending_public is not None and key_derived_id(pending_public) == new:
        return
    hint = _FORCE_HINT.format(old=old.display, new=new.display)
    stored = keys.find(ref_for(old.hex, KeyType.ADMIN_PUBLIC))
    if stored is None:
        _refuse(
            f"{old.display} has no recorded public key, so {new.display} cannot be checked "
            "against the id firmware 2.8 derives from it.",
            old=old,
            new=new,
            hint=hint,
        )
    material = stored.material()
    sharing = sorted(
        record.owner_node_id
        for record in keys.of_type(KeyType.ADMIN_PUBLIC)
        if record.owner_node_id != old.hex
        and is_canonical_node_owner(record.owner_node_id)
        and record.material() == material
    )
    if sharing:
        _refuse(
            f"{old.display}'s recorded public key is also recorded for {', '.join(sharing)}, "
            "so the id derived from it does not tell which node moved.",
            old=old,
            new=new,
            hint=hint,
        )
    derived = key_derived_id(material)
    if derived != new:
        _refuse(
            f"{new.display} is not the id firmware 2.8 derives from {old.display}'s recorded "
            f"public key ({derived.display}).",
            old=old,
            new=new,
            hint=hint,
        )


def _move_keys(keys: KeyRepository, *, old: NodeId, new: NodeId) -> tuple[str, ...]:
    """Re-file ``old``'s own key rows under ``new``, keeping everything but the reference."""
    moved = []
    for key_type in KeyType:
        record = keys.find(ref_for(old.hex, key_type))
        if record is None:
            continue
        keys.delete(record.key_ref)
        keys.upsert(
            KeyRecord(
                key_ref=ref_for(new.hex, key_type),
                owner_node_id=new.hex,
                key_type=key_type,
                key_value=record.key_value,
                created_ts=record.created_ts,
                origin=record.origin,
            )
        )
        moved.append(ref_for(new.hex, key_type))
    return tuple(moved)


def _renamed(refs: tuple[str, ...], renames: Mapping[str, str]) -> tuple[str, ...]:
    """Return ``refs`` with every reference in ``renames`` replaced, order kept."""
    return tuple(renames.get(ref, ref) for ref in refs)


def renumber_rows(
    nodes: NodeRepository, keys: KeyRepository, *, old: NodeId, new: NodeId, now: datetime
) -> Renumbered:
    """Move ``old``'s row, key rows and key references to ``new``, in memory only.

    Call :func:`check_renumber` first; the caller saves.

    Args:
        nodes: The node repository.
        keys: The key repository, sharing ``nodes``' database session.
        old: The id whose row moves.
        new: The id it moves to.
        now: The time recorded on every changed row, and in the note.

    Returns:
        What was moved.

    Raises:
        NodeNotFoundError: If ``old`` has no row.
    """
    record = nodes.get(old)
    moved = _move_keys(keys, old=old, new=new)
    renames = dict(zip(_own_refs(old), _own_refs(new), strict=True))
    note = renumber_note(old, until=now)
    nodes.delete(old)
    nodes.upsert(
        record.with_updates(
            node_id=new.hex,
            notes=append_note(record.notes, note),
            authorized_admin_keys=_renamed(record.authorized_admin_keys, renames),
        ),
        now=now,
    )
    referencing = []
    for other in nodes.all():
        refs = _renamed(other.authorized_admin_keys, renames)
        if refs != other.authorized_admin_keys:
            nodes.upsert(other.with_updates(authorized_admin_keys=refs), now=now)
            referencing.append(other.node_id)
    return Renumbered(
        old=old, new=new, keys=moved, referencing=tuple(sorted(referencing)), note=note
    )
