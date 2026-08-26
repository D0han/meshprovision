"""Regression tests for the lost-update bug that the write lock closes.

Two ``OdsDatabase`` handles opened on the same path race exactly like two
concurrent ``mesh`` processes would -- this is what ``flock``'s
per-open-file-description semantics make possible inside a single pytest
process (see ``meshprovision.db.locking``'s module docstring).
``test_unlocked_sessions_still_lose_the_update`` pins the HIGH-severity
bug *without* the lock; its sibling proves the locked path is safe. The
unlocked baseline exists so the locked test cannot pass for a reason
unrelated to the lock actually working.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from meshprovision.cli.common import CliContext
from meshprovision.config.settings import Settings
from meshprovision.crypto.keys import KeyPair
from meshprovision.db import locking, schema
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.errors import DatabaseLockedError

pytestmark = pytest.mark.unit


def _upsert_node_and_key(db: OdsDatabase, node_id: str, keypair: KeyPair) -> None:
    NodeRepository(db).upsert(NodeRecord(node_id=node_id, hw_model="RAK4631"))
    public_record, _ = KeyRecord.for_keypair(node_id, keypair)
    KeyRepository(db).upsert(public_record)


def test_unlocked_sessions_still_lose_the_update(empty_ods: Path, keypair: KeyPair) -> None:
    handle_a = OdsDatabase(empty_ods)
    handle_a.load()
    _upsert_node_and_key(handle_a, "deadbe01", keypair)

    # B reads the pre-A-save state; nothing stops this without a lock.
    handle_b = OdsDatabase(empty_ods)
    handle_b.load()

    handle_a.save()

    _upsert_node_and_key(handle_b, "beefcafe", keypair)
    handle_b.save()

    final = OdsDatabase(empty_ods)
    final.load()
    node_ids = {row["node_id"] for row in final.rows(schema.NODES_SHEET)}
    key_refs = {row["key_ref"] for row in final.rows(schema.KEYS_SHEET)}

    # B's whole-sheet rewrite from its own stale snapshot silently discards
    # A's row in both sheets -- this is the bug the lock exists to fix.
    assert node_ids == {"beefcafe"}
    assert key_refs == {"beefcafe_pub"}


def test_two_locked_sessions_cannot_interleave_a_lost_update(
    empty_ods: Path, keypair: KeyPair
) -> None:
    handle_a = OdsDatabase(empty_ods)
    handle_a.lock(timeout=0.2)
    handle_a.load()
    _upsert_node_and_key(handle_a, "deadbe01", keypair)

    handle_b = OdsDatabase(empty_ods)
    with pytest.raises(DatabaseLockedError):
        handle_b.lock(timeout=0.1)

    handle_a.save()
    handle_a.unlock()

    handle_b.lock(timeout=0.2)
    handle_b.load()
    _upsert_node_and_key(handle_b, "beefcafe", keypair)
    handle_b.save()
    handle_b.unlock()

    final = OdsDatabase(empty_ods)
    final.load()
    node_ids = {row["node_id"] for row in final.rows(schema.NODES_SHEET)}
    key_refs = {row["key_ref"] for row in final.rows(schema.KEYS_SHEET)}

    assert node_ids == {"deadbe01", "beefcafe"}
    assert key_refs == {"deadbe01_pub", "beefcafe_pub"}


def test_db_session_releases_the_lock_on_exit(empty_ods: Path) -> None:
    ctx = CliContext.build(
        settings=Settings(db_path=empty_ods), non_interactive=True, force_refresh=False
    )
    with ctx.open_database(for_write=True):
        pass

    # A second acquisition succeeding immediately proves DbSession.__exit__
    # actually released the lock -- an incomplete wiring here would hang
    # this test rather than fail an assertion, since tests/e2e/ drives the
    # CLI in-process and depends on exactly this release happening.
    with locking.exclusive_lock(empty_ods, timeout=0.1):
        pass


def test_db_session_releases_the_lock_when_the_block_raises(empty_ods: Path) -> None:
    ctx = CliContext.build(
        settings=Settings(db_path=empty_ods), non_interactive=True, force_refresh=False
    )
    with pytest.raises(RuntimeError, match="boom"), ctx.open_database(for_write=True):
        raise RuntimeError("boom")

    with locking.exclusive_lock(empty_ods, timeout=0.1):
        pass
