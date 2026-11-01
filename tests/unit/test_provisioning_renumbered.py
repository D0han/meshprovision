"""Tests for :mod:`meshprovision.provisioning.renumbered`: a renumbered node at connect time."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository
from meshprovision.db.pending_keys import PendingKeypair
from meshprovision.db.schema import KeyOrigin, KeyType, ManagementMode
from meshprovision.errors import NodeRenumberedError
from meshprovision.nodeid import NodeId, key_derived_id
from meshprovision.provisioning.renumbered import (
    PENDING_KEY_EVIDENCE,
    SAME_KEY_EVIDENCE,
    refuse_renumbered,
    renumber_command,
    renumbered_error,
    renumbered_pending,
    renumbered_row,
)
from tests.unit.apply_fakes import minimal_template
from tests.unit.conftest import make_security

if TYPE_CHECKING:
    from collections.abc import Callable

    from meshprovision.crypto.keys import KeyPair
    from meshprovision.provisioning.detect_types import LiveConfig

pytestmark = pytest.mark.unit

_OLD: Final = NodeId.from_hex("deadbe01")
_EARLIER: Final = datetime(2026, 1, 1, tzinfo=UTC)


def _live(
    make_live: Callable[..., LiveConfig], keypair: KeyPair | None, node: NodeId
) -> LiveConfig:
    security = make_security(keypair=keypair) if keypair is not None else make_security(empty=True)
    return make_live(minimal_template(), node_id=node.hex, security=security)


def _row(nodes: NodeRepository, node: str, **fields: object) -> None:
    nodes.upsert(NodeRecord(node_id=node, management=ManagementMode.TEMPLATE, **fields))


def _key(keys: KeyRepository, owner: str, public: bytes) -> None:
    keys.upsert(
        KeyRecord.from_material(owner, KeyType.ADMIN_PUBLIC, public, origin=KeyOrigin.GENERATED)
    )


def _pending(node: NodeId, keypair: KeyPair) -> PendingKeypair:
    return PendingKeypair(
        node_id=node,
        public=keypair.public,
        private=keypair.private,
        created_ts=_EARLIER,
        path=Path(f"/nonexistent/nodes_db.pending-{node.hex}.json"),
    )


def test_renumber_command_names_both_bare_ids() -> None:
    assert renumber_command(_OLD, NodeId(0x3A7C19E2)) == "mesh db renumber deadbe01 3a7c19e2"


def test_renumbered_error_says_who_it_is_and_hints_the_command() -> None:
    error = renumbered_error(_OLD, NodeId(0x3A7C19E2), evidence=SAME_KEY_EVIDENCE)

    assert error.message == (
        "This is !deadbe01 (same public key) now reporting !3a7c19e2: firmware >= 2.8 derives "
        "the node id from the key."
    )
    assert error.hint is not None
    assert error.hint.endswith("mesh db renumber deadbe01 3a7c19e2")
    assert (error.old, error.new) == ("!deadbe01", "!3a7c19e2")
    assert error.exit_code == 5


def test_the_row_holding_the_devices_key_under_its_old_id_is_found(
    make_live: Callable[..., LiveConfig],
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
) -> None:
    _row(nodes, _OLD.hex, short_name="AB01")
    _key(keys, _OLD.hex, keypair.public)
    live = _live(make_live, keypair, key_derived_id(keypair.public))

    record = renumbered_row(live, nodes=nodes, keys=keys)

    assert record is not None
    assert record.short_name == "AB01"
    with pytest.raises(NodeRenumberedError) as caught:
        refuse_renumbered(live, nodes=nodes, keys=keys)
    assert caught.value.old == _OLD.display
    assert caught.value.new == key_derived_id(keypair.public).display
    assert SAME_KEY_EVIDENCE in caught.value.message


def test_a_device_whose_id_is_not_derived_from_its_key_is_no_renumber(
    make_live: Callable[..., LiveConfig],
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
) -> None:
    """Our key on another, non-derived id is a clone or a restore: other audits own it."""
    _row(nodes, _OLD.hex)
    _key(keys, _OLD.hex, keypair.public)
    live = _live(make_live, keypair, NodeId.from_hex("cafe0002"))

    assert renumbered_row(live, nodes=nodes, keys=keys) is None
    refuse_renumbered(live, nodes=nodes, keys=keys)


def test_a_device_without_a_key_is_no_renumber(
    make_live: Callable[..., LiveConfig], nodes: NodeRepository, keys: KeyRepository
) -> None:
    _row(nodes, _OLD.hex)

    assert renumbered_row(live=_live(make_live, None, _OLD), nodes=nodes, keys=keys) is None


def test_a_key_two_node_rows_hold_names_no_row(
    make_live: Callable[..., LiveConfig],
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
) -> None:
    for node in (_OLD.hex, "cafe0003"):
        _row(nodes, node)
        _key(keys, node, keypair.public)
    live = _live(make_live, keypair, key_derived_id(keypair.public))

    assert renumbered_row(live, nodes=nodes, keys=keys) is None


def test_an_admin_alias_holding_the_key_does_not_count_as_a_node_row(
    make_live: Callable[..., LiveConfig],
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
) -> None:
    _row(nodes, _OLD.hex)
    _key(keys, _OLD.hex, keypair.public)
    _key(keys, "ADMIN1", keypair.public)
    live = _live(make_live, keypair, key_derived_id(keypair.public))

    record = renumbered_row(live, nodes=nodes, keys=keys)

    assert record is not None
    assert record.node_id == _OLD.hex


def test_an_orphan_key_row_under_the_new_id_does_not_hide_the_old_row(
    make_live: Callable[..., LiveConfig],
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
) -> None:
    new = key_derived_id(keypair.public)
    _row(nodes, _OLD.hex)
    _key(keys, _OLD.hex, keypair.public)
    _key(keys, new.hex, keypair.public)

    record = renumbered_row(_live(make_live, keypair, new), nodes=nodes, keys=keys)

    assert record is not None
    assert record.node_id == _OLD.hex


@pytest.mark.parametrize("archived", [True, False], ids=["archived", "no-row"])
def test_a_key_whose_row_is_archived_or_missing_names_no_row(
    make_live: Callable[..., LiveConfig],
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
    archived: bool,
) -> None:
    if archived:
        _row(nodes, _OLD.hex, archived_at=_EARLIER)
    _key(keys, _OLD.hex, keypair.public)
    live = _live(make_live, keypair, key_derived_id(keypair.public))

    assert renumbered_row(live, nodes=nodes, keys=keys) is None


def test_no_pending_keypair_recovers_nothing(
    make_live: Callable[..., LiveConfig], nodes: NodeRepository, keypair: KeyPair
) -> None:
    live = _live(make_live, keypair, key_derived_id(keypair.public))
    assert renumbered_pending(live, None, nodes=nodes) is None


def test_a_pending_keypair_of_an_id_without_a_row_is_recovered(
    make_live: Callable[..., LiveConfig], nodes: NodeRepository, keypair: KeyPair
) -> None:
    pending = _pending(_OLD, keypair)
    live = _live(make_live, keypair, key_derived_id(keypair.public))

    assert renumbered_pending(live, pending, nodes=nodes) is pending


def test_a_pending_keypair_the_device_id_does_not_derive_from_is_not_used(
    make_live: Callable[..., LiveConfig], nodes: NodeRepository, keypair: KeyPair
) -> None:
    live = _live(make_live, keypair, NodeId.from_hex("cafe0002"))
    assert renumbered_pending(live, _pending(_OLD, keypair), nodes=nodes) is None


def test_a_pending_keypair_of_a_live_row_refuses_until_the_row_is_moved(
    make_live: Callable[..., LiveConfig], nodes: NodeRepository, keypair: KeyPair
) -> None:
    _row(nodes, _OLD.hex)
    new = key_derived_id(keypair.public)

    with pytest.raises(NodeRenumberedError) as caught:
        renumbered_pending(_live(make_live, keypair, new), _pending(_OLD, keypair), nodes=nodes)

    assert PENDING_KEY_EVIDENCE in caught.value.message
    assert caught.value.hint is not None
    assert caught.value.hint.endswith(renumber_command(_OLD, new))


def test_a_pending_keypair_of_an_archived_row_is_not_used(
    make_live: Callable[..., LiveConfig], nodes: NodeRepository, keypair: KeyPair
) -> None:
    _row(nodes, _OLD.hex, archived_at=_EARLIER)
    live = _live(make_live, keypair, key_derived_id(keypair.public))

    assert renumbered_pending(live, _pending(_OLD, keypair), nodes=nodes) is None
