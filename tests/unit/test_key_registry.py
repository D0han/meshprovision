"""Tests for :mod:`meshprovision.provisioning.key_registry`.

Exercises :func:`register_observed_key`/:func:`adopt_canonical_ref`
directly against a ``NodeRepository``/``KeyRepository`` pair, independent
of the CLI -- mirroring :mod:`tests.unit.test_admin_custody`'s own
fixtures for the same reason.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from pydantic import SecretStr

from meshprovision.crypto.keys import encode_key
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.schema import KeyType
from meshprovision.errors import DbIntegrityError
from meshprovision.provisioning import observed_keys
from meshprovision.provisioning.key_registry import adopt_canonical_ref, register_observed_key

if TYPE_CHECKING:
    from pathlib import Path

    from meshprovision.crypto.keys import KeyPair

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture
def db(empty_ods: Path) -> OdsDatabase:
    session = OdsDatabase(empty_ods)
    session.load()
    return session


@pytest.fixture
def nodes(db: OdsDatabase) -> NodeRepository:
    return NodeRepository(db)


@pytest.fixture
def keys(db: OdsDatabase) -> KeyRepository:
    return KeyRepository(db)


# ---------------------------------------------------------------------------
# register_observed_key
# ---------------------------------------------------------------------------


def test_register_observed_key_mints_a_new_row(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    # Act
    ref = register_observed_key(nodes, keys, keypair.public, created_ts=_NOW)

    # Assert
    assert ref == observed_keys.observed_key_ref(keypair.public)
    record = keys.find(ref)
    assert record is not None
    assert record.material() == keypair.public
    assert record.created_ts == _NOW


def test_register_observed_key_reuses_an_existing_real_ref(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    # Arrange
    pub, _ = KeyRecord.for_keypair("ADMIN1", keypair)
    keys.upsert(pub)

    # Act
    ref = register_observed_key(nodes, keys, keypair.public, created_ts=_NOW)

    # Assert: no new row minted, the real ref is reused
    assert ref == "ADMIN1_pub"
    assert keys.find(observed_keys.observed_key_ref(keypair.public)) is None


def test_register_observed_key_is_idempotent(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    # Act
    first = register_observed_key(nodes, keys, keypair.public, created_ts=_NOW)
    second = register_observed_key(nodes, keys, keypair.public, created_ts=_NOW)

    # Assert
    assert first == second
    assert len(keys.of_type(KeyType.ADMIN_PUBLIC)) == 1


def test_register_observed_key_prefers_a_node_owned_ref_over_a_stale_observed_one(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    """A key already registered under a real node id wins over its own observed ref."""
    # Arrange: material registered both under a real node id and (as if from
    # an earlier adopt, before this node was known) under an observed ref.
    real_pub, _ = KeyRecord.for_keypair("deadbe01", keypair)
    keys.upsert(real_pub)
    observed_owner = observed_keys.observed_owner(keypair.public)
    keys.upsert(KeyRecord.from_material(observed_owner, KeyType.ADMIN_PUBLIC, keypair.public))

    # Act
    ref = register_observed_key(nodes, keys, keypair.public, created_ts=_NOW)

    # Assert
    assert ref == "deadbe01_pub"


def test_register_observed_key_widens_digest_on_collision(
    nodes: NodeRepository, keys: KeyRepository, keypair_factory
) -> None:  # type: ignore[no-untyped-def]
    """Different material colliding at the narrow ref retries at a wider one."""
    # Arrange: force a collision by occupying the narrow-digest ref with
    # unrelated material.
    a, b = keypair_factory(), keypair_factory()
    narrow_owner = observed_keys.observed_owner(a.public)
    keys.upsert(KeyRecord.from_material(narrow_owner, KeyType.ADMIN_PUBLIC, b.public))

    # Act
    ref = register_observed_key(nodes, keys, a.public, created_ts=_NOW)

    # Assert
    assert ref == observed_keys.observed_key_ref(a.public, chars=16)
    assert keys.find(observed_keys.observed_key_ref(a.public)) is not None  # untouched, still b's


def test_register_observed_key_raises_when_both_widths_collide(
    nodes: NodeRepository, keys: KeyRepository, keypair_factory
) -> None:  # type: ignore[no-untyped-def]
    a, b, c = keypair_factory(), keypair_factory(), keypair_factory()
    narrow_owner = observed_keys.observed_owner(a.public)
    wide_owner = observed_keys.observed_owner(a.public, chars=16)
    keys.upsert(KeyRecord.from_material(narrow_owner, KeyType.ADMIN_PUBLIC, b.public))
    keys.upsert(KeyRecord.from_material(wide_owner, KeyType.ADMIN_PUBLIC, c.public))

    with pytest.raises(DbIntegrityError):
        register_observed_key(nodes, keys, a.public, created_ts=_NOW)


# ---------------------------------------------------------------------------
# adopt_canonical_ref
# ---------------------------------------------------------------------------


def test_adopt_canonical_ref_rewrites_authorized_admin_keys_and_deletes_observed_row(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    # Arrange
    observed_ref = register_observed_key(nodes, keys, keypair.public, created_ts=_NOW)
    node = NodeRecord(node_id="cafe0001", authorized_admin_keys=(observed_ref,))
    nodes.upsert(node)
    keys.upsert(KeyRecord.for_keypair("deadbe01", keypair)[0])

    # Act
    changed = adopt_canonical_ref(nodes, keys, material=keypair.public, canonical_owner="deadbe01")

    # Assert
    assert changed is True
    assert keys.find(observed_ref) is None
    updated = nodes.get("cafe0001")
    assert updated.authorized_admin_keys == ("deadbe01_pub",)


def test_adopt_canonical_ref_dedupes_when_canonical_ref_already_present(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    # Arrange
    observed_ref = register_observed_key(nodes, keys, keypair.public, created_ts=_NOW)
    node = NodeRecord(node_id="cafe0001", authorized_admin_keys=(observed_ref, "deadbe01_pub"))
    nodes.upsert(node)

    # Act
    changed = adopt_canonical_ref(nodes, keys, material=keypair.public, canonical_owner="deadbe01")

    # Assert: no duplicate ref
    assert changed is True
    updated = nodes.get("cafe0001")
    assert updated.authorized_admin_keys == ("deadbe01_pub",)


def test_adopt_canonical_ref_drains_legacy_unregistered_admin_keys(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    # Arrange: a legacy row carrying raw material, never given any ref
    node = NodeRecord(node_id="cafe0001", unregistered_admin_keys=(encode_key(keypair.public),))
    nodes.upsert(node)

    # Act
    changed = adopt_canonical_ref(nodes, keys, material=keypair.public, canonical_owner="deadbe01")

    # Assert
    assert changed is True
    assert nodes.get("cafe0001").unregistered_admin_keys == ()


def test_adopt_canonical_ref_is_a_noop_when_nothing_to_reconcile(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    # Arrange
    node = NodeRecord(node_id="cafe0001", authorized_admin_keys=("ADMIN1_pub",))
    nodes.upsert(node)

    # Act
    changed = adopt_canonical_ref(nodes, keys, material=keypair.public, canonical_owner="deadbe01")

    # Assert
    assert changed is False
    assert nodes.get("cafe0001").authorized_admin_keys == ("ADMIN1_pub",)


class _KeysOfTypeOnly:
    """A minimal KeyRepository double for testing the malformed-row skip in isolation.

    Mirrors :class:`tests.unit.test_verify._KeysAllOnly`'s own reasoning:
    a real ODS load already rejects malformed ``key_value`` material at
    :class:`~meshprovision.db.keys.KeyRecord`'s own field-validator
    construction time, so this "should not happen ... re-checked
    defensively" branch is only reachable by handing
    :func:`~meshprovision.provisioning.key_registry.adopt_canonical_ref`
    a record built via ``model_construct`` (bypassing validation), the
    same way :mod:`tests.unit.test_verify` does for
    ``_check_weak_keys``.
    """

    def __init__(self, records: tuple[KeyRecord, ...]) -> None:
        self._records = records

    def of_type(self, key_type: KeyType) -> tuple[KeyRecord, ...]:
        return tuple(r for r in self._records if r.key_type == key_type)

    def delete(self, key_ref: str) -> bool:
        raise AssertionError(f"delete({key_ref!r}) should never be reached for a malformed row")


class _KeysOfTypeAndDelete(_KeysOfTypeOnly):
    """Extends :class:`_KeysOfTypeOnly` with a delete() that can report a no-op.

    Isolates the loop-continuation branch in :func:`adopt_canonical_ref`'s
    final cleanup: every real ``observed_refs`` entry comes from
    ``of_type()``, so its own ``delete()`` call always succeeds in
    practice -- this double is what lets the "already gone" no-op branch
    be exercised at all.
    """

    def delete(self, key_ref: str) -> bool:
        del key_ref
        return False


def test_adopt_canonical_ref_continues_past_a_delete_that_finds_nothing(
    nodes: NodeRepository, keypair: KeyPair
) -> None:
    """The cleanup loop must keep going even when a delete() call is a no-op."""
    matching = KeyRecord.from_material(
        observed_keys.observed_owner(keypair.public), KeyType.ADMIN_PUBLIC, keypair.public
    )
    node = NodeRecord(
        node_id="cafe0001", authorized_admin_keys=(observed_keys.observed_key_ref(keypair.public),)
    )
    nodes.upsert(node)

    changed = adopt_canonical_ref(
        nodes,
        _KeysOfTypeAndDelete((matching,)),
        material=keypair.public,
        canonical_owner="deadbe01",
    )

    # The node's own ref was still rewritten -- only the (already-gone)
    # Keys row's own deletion was a no-op.
    assert changed is True
    assert nodes.get("cafe0001").authorized_admin_keys == ("deadbe01_pub",)


def test_adopt_canonical_ref_skips_a_malformed_observed_row_without_crashing(
    nodes: NodeRepository, keypair: KeyPair
) -> None:
    """A malformed observed row's material can't be compared -- and must not crash."""
    malformed = KeyRecord.model_construct(
        key_ref="observed-deadbeef_pub",
        owner_node_id="observed-deadbeef",
        key_type=KeyType.ADMIN_PUBLIC,
        key_value=SecretStr("not-valid-base64!!!"),
        created_ts=None,
    )
    node = NodeRecord(node_id="cafe0001", authorized_admin_keys=("observed-deadbeef_pub",))
    nodes.upsert(node)

    # Act / Assert: no KeyMaterialError escapes, and the malformed row's
    # own delete() is never even attempted.
    changed = adopt_canonical_ref(
        nodes, _KeysOfTypeOnly((malformed,)), material=keypair.public, canonical_owner="deadbe01"
    )

    # Assert: nothing matched, so nothing was reconciled.
    assert changed is False
    assert nodes.get("cafe0001").authorized_admin_keys == ("observed-deadbeef_pub",)


def test_adopt_canonical_ref_ignores_an_observed_row_for_different_material(
    nodes: NodeRepository, keys: KeyRepository, keypair_factory
) -> None:  # type: ignore[no-untyped-def]
    """An observed row for a *different* key is left completely alone."""
    a, b = keypair_factory(), keypair_factory()
    unrelated_observed_ref = register_observed_key(nodes, keys, b.public, created_ts=_NOW)
    node = NodeRecord(node_id="cafe0001", authorized_admin_keys=(unrelated_observed_ref,))
    nodes.upsert(node)

    changed = adopt_canonical_ref(nodes, keys, material=a.public, canonical_owner="deadbe01")

    assert changed is False
    assert keys.find(unrelated_observed_ref) is not None
    assert nodes.get("cafe0001").authorized_admin_keys == (unrelated_observed_ref,)


def test_adopt_canonical_ref_deletes_every_matching_observed_row(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    """More than one observed row for the same material (a widened-digest edge case) all go."""
    # Arrange: two observed rows -- as if the default-width ref collided
    # with unrelated material and register_observed_key() had to widen --
    # both happening to hold this exact material (constructed directly
    # here since provoking a real sha256 collision is not feasible).
    narrow_owner = observed_keys.observed_owner(keypair.public)
    wide_owner = observed_keys.observed_owner(keypair.public, chars=16)
    keys.upsert(KeyRecord.from_material(narrow_owner, KeyType.ADMIN_PUBLIC, keypair.public))
    keys.upsert(KeyRecord.from_material(wide_owner, KeyType.ADMIN_PUBLIC, keypair.public))
    node = NodeRecord(
        node_id="cafe0001",
        authorized_admin_keys=(f"{narrow_owner}_pub", f"{wide_owner}_pub"),
    )
    nodes.upsert(node)

    # Act
    changed = adopt_canonical_ref(nodes, keys, material=keypair.public, canonical_owner="deadbe01")

    # Assert: both collapse to the one canonical ref, and both rows are gone.
    assert changed is True
    assert nodes.get("cafe0001").authorized_admin_keys == ("deadbe01_pub",)
    assert keys.find(f"{narrow_owner}_pub") is None
    assert keys.find(f"{wide_owner}_pub") is None


def test_adopt_canonical_ref_handles_both_reconciliations_across_several_nodes(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    """The cloned-key case: two nodes reported the same key, one via each path."""
    # Arrange
    observed_ref = register_observed_key(nodes, keys, keypair.public, created_ts=_NOW)
    node_a = NodeRecord(node_id="aaaa0001", authorized_admin_keys=(observed_ref,))
    node_b = NodeRecord(node_id="bbbb0002", unregistered_admin_keys=(encode_key(keypair.public),))
    nodes.upsert(node_a)
    nodes.upsert(node_b)

    # Act
    changed = adopt_canonical_ref(nodes, keys, material=keypair.public, canonical_owner="deadbe01")

    # Assert
    assert changed is True
    assert nodes.get("aaaa0001").authorized_admin_keys == ("deadbe01_pub",)
    assert nodes.get("bbbb0002").unregistered_admin_keys == ()
    assert keys.find(observed_ref) is None
