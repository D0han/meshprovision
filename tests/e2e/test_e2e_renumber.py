"""Firmware >= 2.8 key-derived node ids, end to end.

Firmware 2.8 renumbers a node to the CRC-32 of its public key. These tests
cover what ``mesh provision`` does about it: a fresh key never derives an id
the database already uses, and ``mesh db renumber`` moves a row (keys, key
references, pending keypair, region memo) to the id the node now reports.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from meshprovision.cli import provision_keys
from meshprovision.crypto.keys import KeyPair, generate_keypair
from meshprovision.datasources.region_memo import REGION_MEMO_FILENAME, RegionMemo
from meshprovision.db import ods, pending_keys
from meshprovision.db.keys import KeyRecord
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import KeyOrigin, KeyType, ManagementMode
from meshprovision.errors import ExitCode
from meshprovision.nodeid import NodeId, key_derived_id
from tests.e2e.conftest import FakeMeshInterface, db_fingerprint, invoke

if TYPE_CHECKING:
    from collections.abc import Callable, Collection

    from click.testing import CliRunner

    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e

_OLD: Final = NodeId.from_hex("deadbe01")


def _seed_keyed(seed_db: Callable[..., Path], keypair: KeyPair, **fields: object) -> Path:
    """Seed ``_OLD`` with ``keypair`` recorded, and a row that names its key as an admin key."""
    pub, priv = KeyRecord.for_keypair(_OLD.hex, keypair, origin=KeyOrigin.GENERATED)
    return seed_db(
        nodes=[
            NodeRecord(node_id=_OLD.hex, management=ManagementMode.TEMPLATE, **fields),
            NodeRecord(
                node_id="cafe0003",
                management=ManagementMode.TEMPLATE,
                authorized_admin_keys=(f"{_OLD.hex}_pub",),
            ),
        ],
        keys=[pub, priv],
    )


def test_a_fresh_key_avoids_the_ids_of_the_other_rows_but_not_its_own(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed_db(
        nodes=[
            NodeRecord(node_id="cafe0001", management=ManagementMode.TEMPLATE),
            NodeRecord(node_id="deadbe01", management=ManagementMode.TEMPLATE),
        ]
    )
    bus.use(FakeMeshInterface("deadbe01"))
    seen: list[Collection[NodeId]] = []

    def spy(taken: Collection[NodeId]) -> KeyPair:
        seen.append(taken)
        return generate_keypair()

    monkeypatch.setattr(provision_keys, "fresh_node_keypair", spy)

    result = invoke(
        runner,
        ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--force-regenerate-key"],
        env,
    )

    assert result.exit_code == 0, result.stderr
    assert seen == [frozenset({NodeId.from_hex("cafe0001")})]


def test_a_fresh_key_avoids_an_id_that_only_owns_key_rows(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A key filed under a node id with no row would block the save after a 2.8 renumber."""
    orphan = KeyRecord.from_material(
        "cafe0002", KeyType.ADMIN_PUBLIC, generate_keypair().public, origin=KeyOrigin.IMPORTED
    )
    alias = KeyRecord.from_material(
        "ADMIN1", KeyType.ADMIN_PUBLIC, generate_keypair().public, origin=KeyOrigin.IMPORTED
    )
    seed_db(
        nodes=[NodeRecord(node_id="deadbe01", management=ManagementMode.TEMPLATE)],
        keys=[orphan, alias],
    )
    bus.use(FakeMeshInterface("deadbe01"))
    seen: list[Collection[NodeId]] = []

    def spy(taken: Collection[NodeId]) -> KeyPair:
        seen.append(taken)
        return generate_keypair()

    monkeypatch.setattr(provision_keys, "fresh_node_keypair", spy)

    result = invoke(
        runner,
        ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--force-regenerate-key"],
        env,
    )

    assert result.exit_code == 0, result.stderr
    assert seen == [frozenset({NodeId.from_hex("cafe0002")})]


def test_db_renumber_moves_the_row_keys_references_pending_keypair_and_region_memo(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], keypair: KeyPair
) -> None:
    db_path = _seed_keyed(seed_db, keypair, short_name="AB01", notes="roof")
    new = key_derived_id(keypair.public)
    pending = generate_keypair()
    pending_keys.write_pending(db_path, _OLD, pending, now=datetime.now(tz=UTC))
    memo_path = Path(env["MESHPROVISION_CACHE_DIR"]) / REGION_MEMO_FILENAME
    RegionMemo(memo_path).remember(_OLD, "Zachód")

    result = invoke(runner, ["db", "renumber", _OLD.hex, new.display, "--yes", "--json"], env)

    assert result.exit_code == 0, result.stderr
    assert f"Renumbered {_OLD.display} to {new.display}." in result.stderr
    assert "admin_nodes names deadbe01" in result.stderr
    document = json.loads(result.stdout)
    assert document["old"] == _OLD.hex
    assert document["new"] == new.hex
    assert document["keys"] == [f"{new.hex}_pub", f"{new.hex}_priv"]
    assert document["referencing"] == ["cafe0003"]
    assert document["note"].startswith("node id was !deadbe01 until ")
    assert document["pending_keypair"] == str(pending_keys.pending_key_path(db_path, new))
    assert document["region_memo"] == "Zachód"

    loaded = ods.load_database(db_path)
    rows = {row["node_id"]: row for row in loaded.nodes}
    assert set(rows) == {new.hex, "cafe0003"}
    assert rows[new.hex]["short_name"] == "AB01"
    assert rows[new.hex]["notes"] == f"roof; {document['note']}"
    assert rows["cafe0003"]["authorized_admin_keys"] == f"{new.hex}_pub"
    assert {row["key_ref"] for row in loaded.keys} == {f"{new.hex}_pub", f"{new.hex}_priv"}
    moved = pending_keys.load_pending(db_path, new)
    assert moved is not None
    assert moved.matches(public=pending.public, private=pending.private)
    assert pending_keys.load_pending(db_path, _OLD) is None
    assert RegionMemo(memo_path).region_for(new) == "Zachód"
    assert RegionMemo(memo_path).region_for(_OLD) is None


def test_db_renumber_refuses_an_id_not_derived_from_the_key_and_changes_nothing(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], keypair: KeyPair
) -> None:
    db_path = _seed_keyed(seed_db, keypair)
    before = db_fingerprint(db_path)

    result = invoke(runner, ["db", "renumber", _OLD.hex, "cafe0002", "--yes"], env)

    assert result.exit_code == ExitCode.DB
    assert f"({key_derived_id(keypair.public).display})" in result.stderr
    assert "--force" in result.stderr
    assert db_fingerprint(db_path) == before


def test_db_renumber_accepts_the_id_derived_from_the_pending_keypair(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], keypair: KeyPair
) -> None:
    """An interrupted regenerate: the device holds the pending key, not the recorded one."""
    db_path = _seed_keyed(seed_db, keypair)
    pending = generate_keypair()
    pending_keys.write_pending(db_path, _OLD, pending, now=datetime.now(tz=UTC))
    new = key_derived_id(pending.public)

    result = invoke(runner, ["db", "renumber", _OLD.hex, new.hex, "--yes"], env)

    assert result.exit_code == 0, result.stderr
    assert {row["node_id"] for row in ods.load_database(db_path).nodes} == {new.hex, "cafe0003"}
    assert pending_keys.load_pending(db_path, new) is not None


def test_db_renumber_force_moves_a_row_to_an_id_the_key_does_not_prove(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], keypair: KeyPair
) -> None:
    db_path = _seed_keyed(seed_db, keypair)

    result = invoke(runner, ["db", "renumber", _OLD.hex, "cafe0002", "--force", "--yes"], env)

    assert result.exit_code == 0, result.stderr
    assert {row["node_id"] for row in ods.load_database(db_path).nodes} == {"cafe0002", "cafe0003"}


def test_db_renumber_refuses_without_confirmation_when_non_interactive(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], keypair: KeyPair
) -> None:
    db_path = _seed_keyed(seed_db, keypair)
    before = db_fingerprint(db_path)

    result = invoke(runner, ["db", "renumber", _OLD.hex, key_derived_id(keypair.public).hex], env)

    assert result.exit_code == ExitCode.PROVISIONING
    assert db_fingerprint(db_path) == before


def test_db_renumber_of_an_unknown_node_is_not_found(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db()

    result = invoke(runner, ["db", "renumber", _OLD.hex, "cafe0002", "--force", "--yes"], env)

    assert result.exit_code == ExitCode.DATASOURCE
    assert "not found" in result.stderr


def test_db_renumber_rejects_a_malformed_id_as_a_usage_error(
    runner: CliRunner, env: dict[str, str]
) -> None:
    result = invoke(runner, ["db", "renumber", _OLD.hex, "not-an-id"], env)

    assert result.exit_code == 2


def test_db_renumber_reminds_about_admin_nodes_whenever_the_public_key_moved(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], keypair: KeyPair
) -> None:
    """No other row references the key yet: the template may still name it."""
    pub, priv = KeyRecord.for_keypair(_OLD.hex, keypair, origin=KeyOrigin.GENERATED)
    seed_db(
        nodes=[NodeRecord(node_id=_OLD.hex, management=ManagementMode.TEMPLATE)], keys=[pub, priv]
    )
    new = key_derived_id(keypair.public)

    result = invoke(runner, ["db", "renumber", _OLD.hex, new.hex, "--yes"], env)

    assert result.exit_code == 0, result.stderr
    assert f"admin_nodes names {_OLD.hex}, change it to {new.hex}" in result.stderr
    assert "references rewritten" not in result.stderr


def test_db_renumber_without_a_public_key_gives_no_admin_nodes_reminder(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db(nodes=[NodeRecord(node_id=_OLD.hex, management=ManagementMode.TEMPLATE)])

    result = invoke(runner, ["db", "renumber", _OLD.hex, "cafe0002", "--force", "--yes"], env)

    assert result.exit_code == 0, result.stderr
    assert "admin_nodes" not in result.stderr


def test_db_renumber_never_overwrites_a_pending_keypair_filed_under_the_new_id(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], keypair: KeyPair
) -> None:
    db_path = _seed_keyed(seed_db, keypair)
    new = key_derived_id(keypair.public)
    theirs = generate_keypair()
    pending_keys.write_pending(db_path, new, theirs, now=datetime.now(tz=UTC))
    before = db_fingerprint(db_path)

    result = invoke(runner, ["db", "renumber", _OLD.hex, new.hex, "--yes", "--force"], env)

    assert result.exit_code == ExitCode.DB
    assert f"A pending keypair is already filed under {new.display}" in result.stderr
    assert db_fingerprint(db_path) == before
    kept = pending_keys.load_pending(db_path, new)
    assert kept is not None
    assert kept.matches(public=theirs.public, private=theirs.private)
