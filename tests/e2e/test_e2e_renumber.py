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


def _device(node: NodeId, keypair: KeyPair, **kwargs: object) -> FakeMeshInterface:
    """A device reporting ``node`` and holding ``keypair``."""
    iface = FakeMeshInterface(node.hex, **kwargs)  # type: ignore[arg-type]
    iface.localNode.localConfig.security.public_key = keypair.public
    iface.localNode.localConfig.security.private_key = keypair.private.reveal()
    return iface


@pytest.mark.parametrize("command", ["provision", "adopt"])
def test_a_node_reporting_the_id_derived_from_a_rows_key_is_refused_with_the_command(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair: KeyPair,
    command: str,
) -> None:
    db_path = _seed_keyed(seed_db, keypair)
    before = db_fingerprint(db_path)
    new = key_derived_id(keypair.public)
    iface = bus.use(_device(new, keypair))

    result = invoke(runner, [command, "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == ExitCode.PROVISIONING
    assert f"This is {_OLD.display} (same public key) now reporting {new.display}" in result.stderr
    assert f"mesh db renumber {_OLD.hex} {new.hex}" in result.stderr
    assert iface.localNode.written_sections == []
    assert db_fingerprint(db_path) == before


def test_our_key_on_an_id_not_derived_from_it_is_not_taken_for_a_renumber(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair: KeyPair,
) -> None:
    _seed_keyed(seed_db, keypair)
    bus.use(_device(NodeId.from_hex("cafe0002"), keypair))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--dry-run"], env)

    assert "mesh db renumber" not in result.stderr


def test_an_interrupted_regenerate_is_followed_through_renumber_to_recovery(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair: KeyPair,
) -> None:
    """The device took the pending key and renumbered; the database still has the old row."""
    pub, priv = KeyRecord.for_keypair(_OLD.hex, keypair, origin=KeyOrigin.GENERATED)
    db_path = seed_db(
        nodes=[NodeRecord(node_id=_OLD.hex, management=ManagementMode.TEMPLATE)], keys=[pub, priv]
    )
    pending = generate_keypair()
    pending_keys.write_pending(db_path, _OLD, pending, now=datetime.now(tz=UTC))
    new = key_derived_id(pending.public)
    bus.use(_device(new, pending))

    refused = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert refused.exit_code == ExitCode.PROVISIONING
    assert "holds the keypair an interrupted `mesh provision` wrote to it" in refused.stderr
    assert f"mesh db renumber {_OLD.hex} {new.hex}" in refused.stderr

    moved = invoke(runner, ["db", "renumber", _OLD.hex, new.hex, "--yes"], env)
    assert moved.exit_code == 0, moved.stderr

    recovered = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert recovered.exit_code == 0, recovered.stderr
    loaded = ods.load_database(db_path)
    assert [row["node_id"] for row in loaded.nodes] == [new.hex]
    records = {row["key_ref"]: KeyRecord.from_row(row) for row in loaded.keys}
    assert records[f"{new.hex}_pub"].material() == pending.public
    assert records[f"{new.hex}_pub"].origin is KeyOrigin.GENERATED
    assert pending_keys.load_pending(db_path, new) is None


def test_an_interrupted_factory_provisioning_is_recovered_under_the_new_id(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    db_path: Path,
) -> None:
    pending = generate_keypair()
    pending_keys.write_pending(db_path, _OLD, pending, now=datetime.now(tz=UTC))
    new = key_derived_id(pending.public)
    # The names landed before the key write, as an interrupted run leaves them.
    bus.use(_device(new, pending, short_name="MT00", long_name="Meshtastic MT00"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0, result.stderr
    assert f"holds the pending keypair of {_OLD.display}" in result.stderr
    loaded = ods.load_database(db_path)
    assert [row["node_id"] for row in loaded.nodes] == [new.hex]
    records = {row["key_ref"]: KeyRecord.from_row(row) for row in loaded.keys}
    assert records[f"{new.hex}_pub"].material() == pending.public
    assert records[f"{new.hex}_pub"].origin is KeyOrigin.GENERATED
    assert pending_keys.load_pending(db_path, _OLD) is None
    assert pending_keys.load_pending(db_path, new) is None


def test_a_pending_keypair_whose_derived_id_the_device_does_not_report_is_left_alone(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    db_path: Path,
) -> None:
    pending = generate_keypair()
    pending_keys.write_pending(db_path, _OLD, pending, now=datetime.now(tz=UTC))
    bus.use(_device(NodeId.from_hex("cafe0002"), pending))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert "holds the pending keypair" not in result.stderr
    assert pending_keys.load_pending(db_path, _OLD) is not None


_FW_28 = "2.8.0.47db0e3"


def _device_28(node: str = _OLD.hex, **kwargs: object) -> FakeMeshInterface:
    """A firmware 2.8 device that renumbers after a key write, its region already set."""
    iface = FakeMeshInterface(node, firmware_version=_FW_28, derive_id_from_key=True, **kwargs)  # type: ignore[arg-type]
    iface.localNode.localConfig.lora.region = 3  # EU_868, as the example template wants
    return iface


def test_a_factory_provisioning_on_firmware_2_8_follows_the_node_to_its_new_id(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, db_path: Path
) -> None:
    iface = bus.use(_device_28())

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0, result.stderr
    new = iface.nid
    public = bytes(iface.localNode.localConfig.security.public_key)
    assert new == key_derived_id(public)
    assert new != _OLD
    assert "Applying this plan changes the node id of !deadbe01" in result.stderr
    assert (
        f"Node {_OLD.display} now reports {new.display} (firmware >= 2.8 derives the node id "
        "from the public key); the database follows it."
    ) in result.stderr
    loaded = ods.load_database(db_path)
    assert [row["node_id"] for row in loaded.nodes] == [new.hex]
    assert loaded.nodes[0]["notes"].startswith("node id was !deadbe01 until ")
    records = {row["key_ref"]: KeyRecord.from_row(row) for row in loaded.keys}
    assert set(records) == {f"{new.hex}_pub", f"{new.hex}_priv"}
    assert records[f"{new.hex}_pub"].material() == public
    assert pending_keys.load_pending(db_path, _OLD) is None
    assert pending_keys.load_pending(db_path, new) is None


def test_a_forced_regenerate_on_firmware_2_8_moves_the_row(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair: KeyPair,
) -> None:
    """A node backing an admin key is refused a new key, so no reference ever moves here."""
    pub, priv = KeyRecord.for_keypair(_OLD.hex, keypair, origin=KeyOrigin.GENERATED)
    row = NodeRecord(
        node_id=_OLD.hex,
        management=ManagementMode.TEMPLATE,
        short_name="MT00",
        long_name="Meshtastic MT00",
        notes="roof",
    )
    db_path = seed_db(nodes=[row], keys=[pub, priv])
    memo_path = Path(env["MESHPROVISION_CACHE_DIR"]) / REGION_MEMO_FILENAME
    RegionMemo(memo_path).remember(_OLD, "Zachód")
    iface = bus.use(_device_28(short_name="MT00", long_name="Meshtastic MT00"))
    iface.localNode.localConfig.security.public_key = keypair.public
    iface.localNode.localConfig.security.private_key = keypair.private.reveal()

    result = invoke(
        runner,
        ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--force-regenerate-key"],
        env,
    )

    assert result.exit_code == 0, result.stderr
    new = iface.nid
    assert new == key_derived_id(bytes(iface.localNode.localConfig.security.public_key))
    loaded = ods.load_database(db_path)
    assert [row["node_id"] for row in loaded.nodes] == [new.hex]
    assert loaded.nodes[0]["short_name"] == "MT00"
    assert loaded.nodes[0]["notes"].startswith("roof; node id was !deadbe01 until ")
    records = {row["key_ref"]: KeyRecord.from_row(row) for row in loaded.keys}
    assert set(records) == {f"{new.hex}_pub", f"{new.hex}_priv"}
    assert records[f"{new.hex}_pub"].material() != keypair.public
    assert RegionMemo(memo_path).region_for(new) == "Zachód"
    assert RegionMemo(memo_path).region_for(_OLD) is None


def test_a_2_8_renumber_whose_save_fails_is_finished_after_mesh_db_renumber(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair: KeyPair,
) -> None:
    """The device moved, the database did not: the next runs find the key and follow it."""
    from meshprovision.db import ods_write

    pub, priv = KeyRecord.for_keypair(_OLD.hex, keypair, origin=KeyOrigin.GENERATED)
    db_path = seed_db(
        nodes=[
            NodeRecord(
                node_id=_OLD.hex,
                management=ManagementMode.TEMPLATE,
                short_name="MT00",
                long_name="Meshtastic MT00",
            )
        ],
        keys=[pub, priv],
    )
    iface = bus.use(_device_28(short_name="MT00", long_name="Meshtastic MT00"))
    iface.localNode.localConfig.security.public_key = keypair.public
    iface.localNode.localConfig.security.private_key = keypair.private.reveal()
    env["MESHPROVISION_LOG_LEVEL"] = "ERROR"

    def _raise(*args: object, **kwargs: object) -> None:
        raise OSError(28, "No space left on device")

    with pytest.MonkeyPatch.context() as save_fails:
        save_fails.setattr(ods_write, "write_database", _raise)
        first = invoke(
            runner,
            ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--force-regenerate-key"],
            env,
        )

    new = iface.nid
    assert first.exit_code == ExitCode.DB
    assert f"The node now reports {new.display}" in first.stderr
    assert [row["node_id"] for row in ods.load_database(db_path).nodes] == [_OLD.hex]

    bus.use(iface)
    refused = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert refused.exit_code == ExitCode.PROVISIONING
    assert f"mesh db renumber {_OLD.hex} {new.hex}" in refused.stderr

    moved = invoke(runner, ["db", "renumber", _OLD.hex, new.hex, "--yes"], env)
    assert moved.exit_code == 0, moved.stderr

    bus.use(iface)
    finished = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert finished.exit_code == 0, finished.stderr
    assert iface.nid == new
    loaded = ods.load_database(db_path)
    assert [row["node_id"] for row in loaded.nodes] == [new.hex]
    records = {row["key_ref"]: KeyRecord.from_row(row) for row in loaded.keys}
    assert records[f"{new.hex}_pub"].material() == bytes(
        iface.localNode.localConfig.security.public_key
    )
    assert pending_keys.load_pending(db_path, new) is None


@pytest.mark.parametrize("dry_run", [False, True], ids=["apply", "dry-run"])
def test_a_firmware_2_8_device_without_a_region_is_refused_before_any_write(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, db_path: Path, dry_run: bool
) -> None:
    iface = FakeMeshInterface(_OLD.hex, firmware_version=_FW_28, derive_id_from_key=True)
    bus.use(iface)
    before = db_fingerprint(db_path)

    args = ["provision", "--port", "/dev/ttyFAKE0", "--yes", *(["--dry-run"] if dry_run else [])]
    result = invoke(runner, args, env)

    assert result.exit_code == ExitCode.PROVISIONING
    assert "has no LoRa region yet" in result.stderr
    assert "meshtastic --set lora.region EU_868" in result.stderr
    assert iface.localNode.written_sections == []
    assert iface.nid == _OLD
    assert db_fingerprint(db_path) == before


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


def test_a_node_with_its_own_row_is_not_refused_for_another_rows_pending_keypair(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair: KeyPair,
) -> None:
    """With a row of its own the node is provisioned as itself; only its own pending file counts."""
    pending = generate_keypair()
    new = key_derived_id(pending.public)
    pub, priv = KeyRecord.for_keypair(_OLD.hex, keypair, origin=KeyOrigin.GENERATED)
    db_path = seed_db(
        nodes=[
            NodeRecord(node_id=_OLD.hex, management=ManagementMode.TEMPLATE),
            NodeRecord(
                node_id=new.hex,
                management=ManagementMode.TEMPLATE,
                short_name="MT00",
                long_name="Meshtastic MT00",
            ),
        ],
        keys=[pub, priv],
    )
    pending_keys.write_pending(db_path, _OLD, pending, now=datetime.now(tz=UTC))
    bus.use(_device(new, pending, short_name="MT00", long_name="Meshtastic MT00"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0, result.stderr
    assert "mesh db renumber" not in result.stderr
    assert pending_keys.load_pending(db_path, _OLD) is not None


def test_adopt_refuses_a_device_holding_a_live_rows_pending_keypair(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair: KeyPair,
) -> None:
    """Adopting it would record one device under two rows."""
    pub, priv = KeyRecord.for_keypair(_OLD.hex, keypair, origin=KeyOrigin.GENERATED)
    db_path = seed_db(
        nodes=[NodeRecord(node_id=_OLD.hex, management=ManagementMode.TEMPLATE)], keys=[pub, priv]
    )
    pending = generate_keypair()
    pending_keys.write_pending(db_path, _OLD, pending, now=datetime.now(tz=UTC))
    new = key_derived_id(pending.public)
    bus.use(_device(new, pending, short_name="MT00", long_name="Meshtastic MT00"))
    before = db_fingerprint(db_path)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == ExitCode.PROVISIONING
    assert "holds the keypair an interrupted `mesh provision` wrote to it" in result.stderr
    assert f"mesh db renumber {_OLD.hex} {new.hex}" in result.stderr
    assert db_fingerprint(db_path) == before


def test_adopt_ignores_a_pending_keypair_whose_id_has_no_row(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, db_path: Path
) -> None:
    pending = generate_keypair()
    pending_keys.write_pending(db_path, _OLD, pending, now=datetime.now(tz=UTC))
    new = key_derived_id(pending.public)
    bus.use(_device(new, pending, short_name="MT00", long_name="Meshtastic MT00"))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0, result.stderr
    assert [row["node_id"] for row in ods.load_database(db_path).nodes] == [new.hex]
