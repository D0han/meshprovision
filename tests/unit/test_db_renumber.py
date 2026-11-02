"""Tests for :mod:`meshprovision.db.renumber`: the guards and the in-memory row move.

The new id in most tests is the one firmware 2.8 derives from the old row's
recorded key (:func:`~meshprovision.nodeid.key_derived_id`), computed from a
fresh keypair, so it is whatever that key gives.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

import pytest

from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.renumber import (
    NOTE_SEPARATOR,
    append_note,
    check_renumber,
    renumber_note,
    renumber_rows,
)
from meshprovision.db.schema import KeyOrigin, KeyType, ManagementMode
from meshprovision.errors import NodeNotFoundError, RenumberRefusedError
from meshprovision.nodeid import BROADCAST_NODE_NUM, NodeId, key_derived_id

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from meshprovision.crypto.keys import KeyPair

pytestmark = pytest.mark.unit

_OLD: Final = NodeId.from_hex("deadbe01")
_THIRD: Final = NodeId.from_hex("cafe0003")
_NOW: Final = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)
_EARLIER: Final = datetime(2026, 1, 1, tzinfo=UTC)


def _seed_node(
    nodes: NodeRepository,
    keys: KeyRepository,
    node: NodeId,
    keypair: KeyPair | None,
    **fields: object,
) -> NodeRecord:
    record = NodeRecord(node_id=node.hex, management=ManagementMode.TEMPLATE, **fields)
    if keypair is not None:
        for key_record in KeyRecord.for_keypair(
            node.hex, keypair, origin=KeyOrigin.GENERATED, created_ts=_EARLIER
        ):
            keys.upsert(key_record)
    nodes.upsert(record, now=_EARLIER)
    return record


def _refused(
    nodes: NodeRepository, keys: KeyRepository, new: NodeId, **kwargs: object
) -> RenumberRefusedError:
    with pytest.raises(RenumberRefusedError) as caught:
        check_renumber(nodes, keys, old=_OLD, new=new, **kwargs)  # type: ignore[arg-type]
    assert caught.value.old == _OLD.display
    assert caught.value.new == new.display
    return caught.value


def test_renumber_note_names_the_old_id_and_the_utc_day() -> None:
    late = datetime(2026, 11, 1, 23, 30, tzinfo=UTC)
    assert renumber_note(_OLD, until=late) == (
        "node id was !deadbe01 until 2026-11-01 (firmware 2.8 key-derived id)"
    )


@pytest.mark.parametrize(
    ("notes", "expected"), [("", "new"), ("old text", f"old text{NOTE_SEPARATOR}new")]
)
def test_append_note_separates_only_a_non_empty_cell(notes: str, expected: str) -> None:
    assert append_note(notes, "new") == expected


def test_the_derived_id_of_the_recorded_key_passes(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    _seed_node(nodes, keys, _OLD, keypair)

    check_renumber(nodes, keys, old=_OLD, new=key_derived_id(keypair.public))


def test_the_same_id_is_refused(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    _seed_node(nodes, keys, _OLD, keypair)
    assert "already has that id" in _refused(nodes, keys, _OLD, force=True).message


@pytest.mark.parametrize("num", [0, 3, BROADCAST_NODE_NUM])
def test_a_reserved_id_is_refused_even_with_force(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair, num: int
) -> None:
    _seed_node(nodes, keys, _OLD, keypair)
    assert "is reserved" in _refused(nodes, keys, NodeId(num), force=True).message


def test_a_missing_old_row_is_not_found(nodes: NodeRepository, keys: KeyRepository) -> None:
    with pytest.raises(NodeNotFoundError):
        check_renumber(nodes, keys, old=_OLD, new=_THIRD, force=True)


def test_an_archived_old_row_is_refused_even_with_force(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    _seed_node(nodes, keys, _OLD, keypair, archived_at=_EARLIER)
    new = key_derived_id(keypair.public)
    assert "archived" in _refused(nodes, keys, new, force=True).message


def test_a_new_id_with_a_row_is_refused_even_with_force(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    new = key_derived_id(keypair.public)
    _seed_node(nodes, keys, _OLD, keypair)
    _seed_node(nodes, keys, new, None)
    assert "already has a row" in _refused(nodes, keys, new, force=True).message


def test_a_new_id_with_stray_key_rows_is_refused_even_with_force(
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    new = key_derived_id(keypair.public)
    _seed_node(nodes, keys, _OLD, keypair)
    keys.upsert(
        KeyRecord.from_material(
            new.hex, KeyType.ADMIN_PUBLIC, keypair_factory().public, origin=KeyOrigin.IMPORTED
        )
    )
    message = _refused(nodes, keys, new, force=True).message
    assert f"{new.hex}_pub" in message
    assert "is not free" in message


def test_without_a_recorded_key_only_force_moves_the_row(
    nodes: NodeRepository, keys: KeyRepository
) -> None:
    _seed_node(nodes, keys, _OLD, None)

    error = _refused(nodes, keys, _THIRD)

    assert "has no recorded public key" in error.message
    assert error.hint is not None
    assert "--force" in error.hint
    check_renumber(nodes, keys, old=_OLD, new=_THIRD, force=True)


def test_an_id_not_derived_from_the_recorded_key_is_refused_naming_the_derived_one(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    _seed_node(nodes, keys, _OLD, keypair)

    error = _refused(nodes, keys, _THIRD)

    assert f"({key_derived_id(keypair.public).display})" in error.message
    assert error.hint is not None
    assert "--force" in error.hint


def test_a_recorded_key_another_node_row_holds_proves_nothing(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    _seed_node(nodes, keys, _OLD, keypair)
    _seed_node(nodes, keys, _THIRD, keypair)

    error = _refused(nodes, keys, key_derived_id(keypair.public))

    assert "also recorded for cafe0003" in error.message


def test_a_recorded_key_an_admin_alias_also_holds_still_proves_the_id(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    _seed_node(nodes, keys, _OLD, keypair)
    keys.upsert(
        KeyRecord.from_material(
            "ADMIN1", KeyType.ADMIN_PUBLIC, keypair.public, origin=KeyOrigin.IMPORTED
        )
    )

    check_renumber(nodes, keys, old=_OLD, new=key_derived_id(keypair.public))


def test_a_pending_keypair_proves_the_id_it_derives(
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    pending = keypair_factory()
    _seed_node(nodes, keys, _OLD, keypair)
    new = key_derived_id(pending.public)

    check_renumber(nodes, keys, old=_OLD, new=new, pending_public=pending.public)


def test_a_pending_keypair_deriving_another_id_still_needs_the_recorded_key(
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    _seed_node(nodes, keys, _OLD, keypair)
    pending = keypair_factory()

    _refused(nodes, keys, _THIRD, pending_public=pending.public)
    check_renumber(
        nodes, keys, old=_OLD, new=key_derived_id(keypair.public), pending_public=pending.public
    )


def _admin_referencing(nodes: NodeRepository, node: NodeId, refs: tuple[str, ...]) -> None:
    nodes.upsert(
        NodeRecord(
            node_id=node.hex, management=ManagementMode.TEMPLATE, authorized_admin_keys=refs
        ),
        now=_EARLIER,
    )


def test_renumber_rows_moves_the_row_keeping_its_fields_and_adding_the_note(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    new = key_derived_id(keypair.public)
    _seed_node(nodes, keys, _OLD, keypair, short_name="AB01", long_name="Alpha", notes="roof")

    moved = renumber_rows(nodes, keys, old=_OLD, new=new, now=_NOW)

    assert nodes.find(_OLD) is None
    row = nodes.get(new)
    assert (row.short_name, row.long_name, row.management) == (
        "AB01",
        "Alpha",
        ManagementMode.TEMPLATE,
    )
    assert row.notes == f"roof{NOTE_SEPARATOR}{moved.note}"
    assert moved.note == renumber_note(_OLD, until=_NOW)
    assert row.first_added_ts == _EARLIER
    assert row.last_updated_ts == _NOW
    assert (moved.old, moved.new) == (_OLD, new)


def test_renumber_rows_refiles_every_own_key_row_unchanged_but_for_its_reference(
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    new = key_derived_id(keypair.public)
    _seed_node(nodes, keys, _OLD, keypair)
    psk = keypair_factory().public
    keys.upsert(
        KeyRecord.from_material(
            _OLD.hex, KeyType.CHANNEL_PSK, psk, origin=KeyOrigin.IMPORTED, created_ts=_EARLIER
        )
    )

    moved = renumber_rows(nodes, keys, old=_OLD, new=new, now=_NOW)

    assert moved.keys == (f"{new.hex}_pub", f"{new.hex}_priv", f"{new.hex}_psk")
    assert [record.key_ref for record in keys.all() if record.owner_node_id == _OLD.hex] == []
    public = keys.get(f"{new.hex}_pub")
    assert public.material() == keypair.public
    assert (public.owner_node_id, public.origin, public.created_ts) == (
        new.hex,
        KeyOrigin.GENERATED,
        _EARLIER,
    )
    assert keys.get(f"{new.hex}_priv").secret() == keypair.private
    assert keys.get(f"{new.hex}_psk").material() == psk
    assert keys.keypair_for(new.hex).public == keypair.public


def test_renumber_rows_rewrites_every_reference_and_names_the_rows_it_changed(
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    new = key_derived_id(keypair.public)
    _seed_node(nodes, keys, _OLD, keypair)
    keys.upsert(
        KeyRecord.from_material(
            "ADMIN1", KeyType.ADMIN_PUBLIC, keypair_factory().public, origin=KeyOrigin.IMPORTED
        )
    )
    _admin_referencing(nodes, _THIRD, ("ADMIN1_pub", f"{_OLD.hex}_pub"))
    untouched = NodeId.from_hex("cafe0004")
    _admin_referencing(nodes, untouched, ("ADMIN1_pub",))

    moved = renumber_rows(nodes, keys, old=_OLD, new=new, now=_NOW)

    assert nodes.get(_THIRD).authorized_admin_keys == ("ADMIN1_pub", f"{new.hex}_pub")
    assert nodes.get(_THIRD).last_updated_ts == _NOW
    assert nodes.get(untouched).authorized_admin_keys == ("ADMIN1_pub",)
    assert nodes.get(untouched).last_updated_ts == _EARLIER
    assert moved.referencing == (_THIRD.hex,)


def test_renumber_rows_rewrites_a_reference_on_the_moved_row_itself(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    new = key_derived_id(keypair.public)
    _seed_node(nodes, keys, _OLD, keypair, authorized_admin_keys=(f"{_OLD.hex}_pub",))

    moved = renumber_rows(nodes, keys, old=_OLD, new=new, now=_NOW)

    assert nodes.get(new).authorized_admin_keys == (f"{new.hex}_pub",)
    assert moved.referencing == ()


def test_a_renumbered_database_saves_and_loads_back(empty_ods: Path, keypair: KeyPair) -> None:
    session = OdsDatabase(empty_ods)
    session.load()
    nodes, keys = NodeRepository(session), KeyRepository(session)
    new = key_derived_id(keypair.public)
    _seed_node(nodes, keys, _OLD, keypair)
    _admin_referencing(nodes, _THIRD, (f"{_OLD.hex}_pub",))

    renumber_rows(nodes, keys, old=_OLD, new=new, now=_NOW)
    session.save()

    reloaded = OdsDatabase(empty_ods)
    reloaded.load()
    assert {record.node_id for record in NodeRepository(reloaded).all()} == {new.hex, _THIRD.hex}
    assert NodeRepository(reloaded).get(_THIRD).authorized_admin_keys == (f"{new.hex}_pub",)
    assert KeyRepository(reloaded).keypair_for(new.hex).public == keypair.public


def test_a_pending_keypair_under_the_new_id_is_refused_even_with_force(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    _seed_node(nodes, keys, _OLD, keypair)
    new = key_derived_id(keypair.public)

    error = _refused(nodes, keys, new, new_has_pending=True, force=True)

    assert "pending keypair is already filed" in error.message
    assert error.hint is not None
    assert "mesh provision" in error.hint
