"""Tests for :func:`meshprovision.cli.adopt.resolve_node_id`'s public-key tier.

Exercises ``resolve_node_id`` directly against a ``KeyRepository`` built
over a throwaway :func:`empty_ods` file -- never the project's own
database -- with ``no_lookup=True`` so the loranet advisory tier never
runs and ``ctx`` is never touched.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from meshprovision.cli.adopt import resolve_node_id
from meshprovision.cli.common import CliContext
from meshprovision.config.settings import Settings
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.schema import KeyOrigin, KeyType
from meshprovision.errors import NodeIdentityError
from meshprovision.provisioning.backup import BackupBundle, NodeDbEntry

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from meshprovision.crypto.keys import KeyPair

pytestmark = pytest.mark.unit


@pytest.fixture
def db_keys(empty_ods: Path) -> KeyRepository:
    session = OdsDatabase(empty_ods)
    session.load()
    return KeyRepository(session)


@pytest.fixture
def ctx() -> CliContext:
    return CliContext.build(settings=Settings(), non_interactive=True, force_refresh=False)


def _bundle_for(public_key: bytes) -> BackupBundle:
    """Build a bundle whose ``public_key`` is ``public_key``, nothing else."""
    entry = NodeDbEntry(
        num=0,
        node_id=None,
        long_name=None,
        short_name=None,
        hw_model=None,
        role=None,
        public_key=public_key,
        firmware_version=None,
    )
    return BackupBundle(profile=None, nodedb_entry=entry)


def test_resolves_to_the_canonical_owner_ignoring_a_non_canonical_label_match(
    db_keys: KeyRepository,
    ctx: CliContext,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """``"c1"`` looks hex-shaped to ``NodeId.try_parse`` but doesn't round-trip."""
    key = keypair_factory().public
    db_keys.upsert(
        KeyRecord.from_material("c1", KeyType.ADMIN_PUBLIC, key, origin=KeyOrigin.CAPTURED)
    )
    db_keys.upsert(
        KeyRecord.from_material("deadbe01", KeyType.ADMIN_PUBLIC, key, origin=KeyOrigin.CAPTURED)
    )

    node_id = resolve_node_id(
        ctx,
        _bundle_for(key),
        node_id_opt=None,
        db_keys=db_keys,
        no_lookup=True,
        force=False,
    )

    assert node_id.hex == "deadbe01"


def test_a_non_canonical_only_match_falls_through_to_the_could_not_determine_error(
    db_keys: KeyRepository,
    ctx: CliContext,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """``"2024"`` parses as decimal but doesn't round-trip either -- no genuine match."""
    key = keypair_factory().public
    db_keys.upsert(
        KeyRecord.from_material("2024", KeyType.ADMIN_PUBLIC, key, origin=KeyOrigin.CAPTURED)
    )

    with pytest.raises(NodeIdentityError, match="Could not determine this node's id"):
        resolve_node_id(
            ctx,
            _bundle_for(key),
            node_id_opt=None,
            db_keys=db_keys,
            no_lookup=True,
            force=False,
        )


def test_two_distinct_canonical_owners_with_no_explicit_node_id_raise_ambiguity_error(
    db_keys: KeyRepository,
    ctx: CliContext,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    key = keypair_factory().public
    db_keys.upsert(
        KeyRecord.from_material("deadbe01", KeyType.ADMIN_PUBLIC, key, origin=KeyOrigin.CAPTURED)
    )
    db_keys.upsert(
        KeyRecord.from_material("deadbe02", KeyType.ADMIN_PUBLIC, key, origin=KeyOrigin.CAPTURED)
    )

    with pytest.raises(NodeIdentityError) as exc_info:
        resolve_node_id(
            ctx,
            _bundle_for(key),
            node_id_opt=None,
            db_keys=db_keys,
            no_lookup=True,
            force=False,
        )

    assert set(exc_info.value.candidates) == {"!deadbe01", "!deadbe02"}
