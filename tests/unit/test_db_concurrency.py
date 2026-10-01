"""Regression tests for the lost-update bug that the write lock closes.

Two ``OdsDatabase`` handles opened on the same path race exactly like two
concurrent ``mesh`` processes would -- this is what ``flock``'s
per-open-file-description semantics make possible inside a single pytest
process (see ``meshprovision.db.locking``'s module docstring).

``test_unlocked_sessions_are_refused_by_the_concurrent_modification_check``
pins what an *unlocked* pair of sessions gets today, since C38-1 added
``OdsDatabase.save``'s own concurrent-modification check (see
``meshprovision.db.ods.OdsDatabase._check_not_concurrently_modified``):
that check compares file identity/content, not any lock, so it
independently catches this exact single-process race too -- B's blind
rewrite from its own stale snapshot is refused with
``DbConcurrentModificationError`` instead of the HIGH-severity silent
data loss this test used to pin (B's save used to discard A's row in
both sheets outright). Its sibling proves the *locked* path still
succeeds outright, which the concurrent-modification check alone cannot
do -- a refused session still has to reload and retry by hand, whereas
``lock()`` lets two genuinely concurrent writers both succeed without
either one failing. The unlocked baseline exists so the locked test
cannot pass for a reason unrelated to the lock actually working.
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
from meshprovision.db.schema import KeyOrigin
from meshprovision.errors import DatabaseLockedError, DbConcurrentModificationError

pytestmark = pytest.mark.unit


def _upsert_node_and_key(db: OdsDatabase, node_id: str, keypair: KeyPair) -> None:
    NodeRepository(db).upsert(NodeRecord(node_id=node_id, hw_model="RAK4631"))
    public_record, _ = KeyRecord.for_keypair(node_id, keypair, origin=KeyOrigin.CAPTURED)
    KeyRepository(db).upsert(public_record)


def test_unlocked_sessions_are_refused_by_the_concurrent_modification_check(
    empty_ods: Path, keypair: KeyPair
) -> None:
    """Without the lock, B's stale save is refused rather than silently discarding A's row.

    Before C38-1 added ``OdsDatabase.save``'s own concurrent-modification
    check, B's whole-sheet rewrite from its own stale snapshot silently
    discarded A's row in both sheets here -- the original HIGH-severity
    bug the write lock exists to fix. B's save() now detects its own
    snapshot is stale (A's save changed the file's content since B's
    load()) and refuses outright instead, leaving A's row intact. A lock
    is still what is needed for B's own change to actually succeed
    without B having to reload and retry by hand -- see
    ``test_two_locked_sessions_cannot_interleave_a_lost_update`` below.
    """
    handle_a = OdsDatabase(empty_ods)
    handle_a.load()
    _upsert_node_and_key(handle_a, "deadbe01", keypair)

    # B reads the pre-A-save state; nothing about *locking* stops this.
    handle_b = OdsDatabase(empty_ods)
    handle_b.load()

    handle_a.save()

    _upsert_node_and_key(handle_b, "beefcafe", keypair)
    with pytest.raises(DbConcurrentModificationError):
        handle_b.save()

    final = OdsDatabase(empty_ods)
    final.load()
    node_ids = {row["node_id"] for row in final.rows(schema.NODES_SHEET)}
    key_refs = {row["key_ref"] for row in final.rows(schema.KEYS_SHEET)}

    # A's row survives: B's refused save never reached the file.
    assert node_ids == {"deadbe01"}
    assert key_refs == {"deadbe01_pub"}


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


def test_db_session_releases_the_lock_on_exit(
    empty_ods: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A LibreOffice lock-marker file present next to the database (e.g.
    # someone has it open in Calc) must produce a warning on a for_write
    # open -- best-effort, never blocking -- see
    # CliContext._warn_if_libreoffice_lock_marker_present (C38-1).
    resolved = empty_ods.resolve()
    lock_marker = resolved.parent / f".~lock.{resolved.name}#"
    lock_marker.write_text("")

    ctx = CliContext.build(
        settings=Settings(db_path=empty_ods), non_interactive=True, force_refresh=False
    )
    with ctx.open_database(for_write=True):
        pass

    assert "LibreOffice" in capsys.readouterr().err

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


def test_open_database_must_exist_false_observes_a_concurrent_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression test for the create-without-a-lock race (Round 37 B7).

    ``mesh db restore`` takes the write lock *before* it writes the missing
    live database. An ``open_database(must_exist=False)`` call racing it
    (``mesh init``'s path) must observe that lock -- and thus never reach
    ``create_empty`` -- instead of checking ``is_file()`` unlocked while the
    restore is still in flight and then clobbering whatever it just wrote.
    """
    db_path = tmp_path / "nodes_db.ods"
    monkeypatch.setenv("MESHPROVISION_LOCK_TIMEOUT", "0")
    ctx = CliContext.build(
        settings=Settings(db_path=db_path), non_interactive=True, force_refresh=False
    )

    # No DB file exists yet -- simulates the restore having taken the lock
    # but not yet written the file.
    with locking.exclusive_lock(db_path, timeout=1.0), pytest.raises(DatabaseLockedError):
        ctx.open_database(must_exist=False)

    # The create-if-missing path must not have run while the lock was held.
    assert not db_path.exists()
