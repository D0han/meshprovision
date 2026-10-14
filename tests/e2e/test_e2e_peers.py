"""``mesh peers`` and the ``sync_peers`` provisioning step against a fake device NodeDB."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from meshprovision.cli import peers_sync
from meshprovision.crypto.known_bad_keys import SMALL_ORDER_POINTS
from meshprovision.db.keys import KeyRecord
from meshprovision.db.node_record import NodeRecord
from meshprovision.db.schema import KeyOrigin, KeyType, ManagementMode
from meshprovision.nodeid import NodeId
from tests.conftest import BASE64_KEY_RE
from tests.e2e.conftest import FakeMeshInterface, db_fingerprint, invoke

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from click.testing import CliRunner

    from meshprovision.crypto.keys import KeyPair
    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e

SELF_HEX = "deadbe01"
B_HEX = "b0000002"
C_HEX = "c0000003"
D_HEX = "d0000004"
E_HEX = "e0000005"
# Realistic key bytes: a repeated-byte key would fail the weak-key audit.
KEY_SELF = hashlib.sha256(b"self").digest()
KEY_B = hashlib.sha256(b"b").digest()
OTHER_KEY = hashlib.sha256(b"other").digest()
PORT_ARGS = ["--port", "/dev/ttyFAKE0"]


def _node(node_hex: str, *, role: str = "CLIENT", archived: bool = False) -> NodeRecord:
    return NodeRecord(
        node_id=node_hex,
        short_name=node_hex[:4].upper(),
        long_name=f"Fleet {node_hex}",
        hw_model="RAK4631",
        role=role,
        archived_at=datetime(2026, 1, 1, tzinfo=UTC) if archived else None,
    )


def _pub(node_hex: str, key: bytes) -> KeyRecord:
    return KeyRecord.from_material(node_hex, KeyType.ADMIN_PUBLIC, key, origin=KeyOrigin.CAPTURED)


def _b64(key: bytes) -> str:
    return base64.b64encode(key).decode("ascii")


@pytest.fixture
def fleet(seed_db: Callable[..., Path]) -> Path:
    """Seed a fleet: this device and B with keys, C without a key, D archived."""
    return seed_db(
        nodes=[
            _node(SELF_HEX, role="ROUTER"),
            _node(B_HEX, role="ROUTER"),
            _node(C_HEX),
            _node(D_HEX, archived=True),
        ],
        keys=[_pub(SELF_HEX, KEY_SELF), _pub(B_HEX, KEY_B)],
    )


def test_dry_run_reports_and_writes_nothing(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    device = bus.use(FakeMeshInterface(SELF_HEX))
    before = db_fingerprint(fleet)

    result = invoke(runner, ["peers", *PORT_ARGS], env)

    assert result.exit_code == 0
    assert "need changes" in result.stderr
    assert f"!{B_HEX}: add contact + favorite" in result.stderr
    assert device.peer_calls == []
    assert device.known_nodes == {}
    assert db_fingerprint(fleet) == before


def test_apply_adds_and_favorites_the_fleet_and_is_idempotent(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    device = bus.use(FakeMeshInterface(SELF_HEX))
    before = db_fingerprint(fleet)

    first = invoke(runner, ["peers", *PORT_ARGS, "--apply"], env)

    assert first.exit_code == 0
    held = device.known_nodes[int(NodeId.parse(B_HEX))]
    assert held["isFavorite"] is True
    assert held["user"]["publicKey"] == _b64(KEY_B)  # type: ignore[index]
    # Neither this device, the key-less node, nor the archived node is touched.
    assert set(device.known_nodes) == {int(NodeId.parse(B_HEX))}
    assert "No public key recorded for" in first.stderr
    assert "Peers synced: 1 node(s) updated." in first.stderr
    assert "after reconnecting" not in first.stderr
    assert db_fingerprint(fleet) == before

    calls_after_first = list(device.peer_calls)
    second = invoke(runner, ["peers", *PORT_ARGS, "--apply"], env)

    assert second.exit_code == 0
    # C still has no key, so the run is not reported as "in sync".
    assert "Nothing to write; 1 node(s) left as reported above." in second.stderr
    assert device.peer_calls == calls_after_first


def test_a_fully_synced_device_is_reported_in_sync(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    seed_db(
        nodes=[_node(SELF_HEX), _node(B_HEX)],
        keys=[_pub(SELF_HEX, KEY_SELF), _pub(B_HEX, KEY_B)],
    )
    device = bus.use(FakeMeshInterface(SELF_HEX))
    b_num = int(NodeId.parse(B_HEX))
    device.known_nodes[b_num] = {
        "num": b_num,
        "user": {"publicKey": _b64(KEY_B)},
        "isFavorite": True,
    }

    result = invoke(runner, ["peers", *PORT_ARGS, "--apply"], env)

    assert result.exit_code == 0
    assert "Peers are in sync: nothing to change." in result.stderr
    assert device.peer_calls == []


def test_known_but_unfavorited_nodes_are_only_favorited(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    device = bus.use(FakeMeshInterface(SELF_HEX))
    b_num, c_num = int(NodeId.parse(B_HEX)), int(NodeId.parse(C_HEX))
    device.known_nodes[b_num] = {"num": b_num, "user": {"publicKey": _b64(KEY_B)}}
    device.known_nodes[c_num] = {"num": c_num, "user": {"id": f"!{C_HEX}"}}

    result = invoke(runner, ["peers", *PORT_ARGS, "--apply"], env)

    assert result.exit_code == 0
    assert sorted(device.peer_calls) == [("fav", b_num), ("fav", c_num)]
    assert device.known_nodes[b_num]["isFavorite"] is True
    assert device.known_nodes[c_num]["isFavorite"] is True


def test_a_different_key_on_the_device_is_reported_and_never_overwritten(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    device = bus.use(FakeMeshInterface(SELF_HEX))
    b_num = int(NodeId.parse(B_HEX))
    device.known_nodes[b_num] = {"num": b_num, "user": {"publicKey": _b64(OTHER_KEY)}}

    result = invoke(runner, ["peers", *PORT_ARGS, "--apply"], env)

    assert result.exit_code == 0
    assert "different public key" in result.stderr
    assert device.peer_calls == []
    assert device.known_nodes[b_num]["user"]["publicKey"] == _b64(OTHER_KEY)  # type: ignore[index]


def test_mismatch_and_keyless_only_is_not_reported_as_in_sync(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    device = bus.use(FakeMeshInterface(SELF_HEX))
    b_num = int(NodeId.parse(B_HEX))
    device.known_nodes[b_num] = {
        "num": b_num,
        "user": {"publicKey": _b64(OTHER_KEY)},
        "isFavorite": True,
    }

    result = invoke(runner, ["peers", *PORT_ARGS, "--apply"], env)

    assert result.exit_code == 0
    assert "in sync" not in result.stderr
    assert "Nothing to write; 2 node(s) left as reported above." in result.stderr
    assert device.peer_calls == []


def test_weak_or_shared_keys_are_reported_and_never_sent(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    shared = hashlib.sha256(b"cloned").digest()
    seed_db(
        nodes=[_node(SELF_HEX), _node(B_HEX), _node(C_HEX), _node(D_HEX)],
        keys=[
            _pub(SELF_HEX, KEY_SELF),
            _pub(B_HEX, shared),
            _pub(C_HEX, shared),
            _pub(D_HEX, SMALL_ORDER_POINTS[1]),
        ],
    )
    device = bus.use(FakeMeshInterface(SELF_HEX))

    result = invoke(runner, ["peers", *PORT_ARGS, "--apply", "--json"], env)

    assert result.exit_code == 0
    assert device.peer_calls == []
    assert device.known_nodes == {}
    assert result.stderr.count("failed the weak-key audit") == 3
    assert "Nothing to write; 3 node(s) left as reported above." in result.stderr
    document = json.loads(result.stdout)
    assert document["weak_key"] == [f"!{B_HEX}", f"!{C_HEX}", f"!{D_HEX}"]
    assert document["to_change"] == []
    assert not BASE64_KEY_RE.search(result.stdout + result.stderr)


def test_a_keyless_node_held_under_a_cloned_key_is_never_favorited(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    device = bus.use(FakeMeshInterface(SELF_HEX))
    b_num, c_num = int(NodeId.parse(B_HEX)), int(NodeId.parse(C_HEX))
    device.known_nodes[b_num] = {
        "num": b_num,
        "user": {"publicKey": _b64(KEY_B)},
        "isFavorite": True,
    }
    device.known_nodes[c_num] = {"num": c_num, "user": {"publicKey": _b64(KEY_B)}}

    result = invoke(runner, ["peers", *PORT_ARGS, "--apply", "--json"], env)

    assert result.exit_code == 0
    assert device.peer_calls == []
    assert f"!{C_HEX}: the database records no public key and the key the device holds" in (
        result.stderr
    )
    assert f"shared with !{B_HEX}" in result.stderr
    document = json.loads(result.stdout)
    assert document["weak_key"] == [f"!{C_HEX}"]
    assert document["no_key"] == []
    assert not BASE64_KEY_RE.search(result.stdout + result.stderr)


def test_provision_never_sends_a_weak_peer_key(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    seed_db(
        nodes=[_node(B_HEX), _node(E_HEX)],
        keys=[_pub(B_HEX, SMALL_ORDER_POINTS[1]), _pub(E_HEX, KEY_B)],
    )
    device = bus.use(FakeMeshInterface("a1b2c3d4"))

    result = invoke(runner, ["provision", *PORT_ARGS, "--yes"], env)

    assert result.exit_code == 0
    assert set(device.known_nodes) == {int(NodeId.parse(E_HEX))}
    assert f"!{B_HEX}: its recorded public key failed the weak-key audit" in result.stderr
    assert "Peer sync incomplete" not in result.stderr


def test_a_write_the_device_silently_drops_fails_the_read_back(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    device = bus.use(FakeMeshInterface(SELF_HEX))
    device.drop_peer_writes = True

    result = invoke(runner, ["peers", *PORT_ARGS, "--apply"], env)

    assert result.exit_code == 5
    assert f"Sent, but the device does not show !{B_HEX} after reconnecting." in result.stderr
    assert "favorited after reconnecting" not in result.stderr
    assert "Peers synced" not in result.stderr


def test_a_rejected_write_is_reported_and_fails_the_run(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    device = bus.use(FakeMeshInterface(SELF_HEX))
    device.fail_peer_writes = True

    result = invoke(runner, ["peers", *PORT_ARGS, "--apply", "--json"], env)

    assert result.exit_code == 5
    assert f"!{B_HEX}: simulated contact write failure" in result.stderr
    assert "Peers synced" not in result.stderr
    document = json.loads(result.stdout)
    assert document["failed"] == [{"node": f"!{B_HEX}", "error": "simulated contact write failure"}]
    assert document["unconfirmed"] == [f"!{B_HEX}"]


def test_json_output_names_nodes_but_carries_no_key_material(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    bus.use(FakeMeshInterface(SELF_HEX))

    result = invoke(runner, ["peers", *PORT_ARGS, "--apply", "--json"], env)

    document = json.loads(result.stdout)
    assert document["node"] == f"!{SELF_HEX}"
    assert document["applied"] is True
    assert [entry["node"] for entry in document["to_change"]] == [f"!{B_HEX}"]
    assert document["no_key"] == [f"!{C_HEX}"]
    assert document["weak_key"] == []
    assert document["unconfirmed"] == []
    assert not BASE64_KEY_RE.search(result.stdout + result.stderr)


def test_peers_json_reports_each_node_under_the_right_key(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    """The keys scripts read: to_change entries, in_sync, key_mismatch, no_key, failed."""
    f_hex = "f0000006"
    key_e = hashlib.sha256(b"e").digest()
    seed_db(
        nodes=[_node(SELF_HEX), _node(B_HEX), _node(C_HEX), _node(E_HEX), _node(f_hex)],
        keys=[_pub(B_HEX, KEY_B), _pub(E_HEX, key_e), _pub(f_hex, hashlib.sha256(b"f").digest())],
    )
    device = bus.use(FakeMeshInterface(SELF_HEX))
    b_num, e_num = int(NodeId.parse(B_HEX)), int(NodeId.parse(E_HEX))
    device.known_nodes[b_num] = {
        "num": b_num,
        "user": {"publicKey": _b64(KEY_B)},
        "isFavorite": True,
    }
    device.known_nodes[e_num] = {"num": e_num, "user": {"publicKey": _b64(OTHER_KEY)}}

    result = invoke(runner, ["peers", *PORT_ARGS, "--json"], env)

    document = json.loads(result.stdout)
    assert document["to_change"] == [{"node": f"!{f_hex}", "add_contact": True, "favorite": True}]
    assert document["in_sync"] == [f"!{B_HEX}"]
    assert document["key_mismatch"] == [f"!{E_HEX}"]
    assert document["no_key"] == [f"!{C_HEX}"]
    assert document["failed"] == []


def _favorited_archived_d(device: FakeMeshInterface) -> int:
    d_num = int(NodeId.parse(D_HEX))
    device.known_nodes[d_num] = {
        "num": d_num,
        "user": {"publicKey": _b64(OTHER_KEY)},
        "isFavorite": True,
    }
    return d_num


def test_prune_archived_dry_run_reports_and_writes_nothing(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    device = bus.use(FakeMeshInterface(SELF_HEX))
    d_num = _favorited_archived_d(device)

    result = invoke(runner, ["peers", *PORT_ARGS, "--prune-archived"], env)

    assert result.exit_code == 0
    assert f"!{D_HEX}: archived in the database; unfavorite" in result.stderr
    assert "2 node(s) need changes" in result.stderr
    assert device.peer_calls == []
    assert device.known_nodes[d_num]["isFavorite"] is True


def test_prune_archived_apply_unfavorites_and_is_idempotent(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    device = bus.use(FakeMeshInterface(SELF_HEX))
    d_num = _favorited_archived_d(device)

    first = invoke(runner, ["peers", *PORT_ARGS, "--apply", "--prune-archived", "--json"], env)

    assert first.exit_code == 0
    assert ("unfav", d_num) in device.peer_calls
    # Unfavorited only: the device keeps the node (and its key) in its NodeDB.
    assert device.known_nodes[d_num]["isFavorite"] is False
    assert device.known_nodes[d_num]["user"]["publicKey"] == _b64(OTHER_KEY)  # type: ignore[index]
    assert json.loads(first.stdout)["unfavorite"] == [f"!{D_HEX}"]
    assert "1 archived node(s) unfavorited" in first.stderr

    calls_after_first = list(device.peer_calls)
    second = invoke(runner, ["peers", *PORT_ARGS, "--apply", "--prune-archived"], env)

    assert second.exit_code == 0
    assert device.peer_calls == calls_after_first


def test_apply_without_prune_archived_leaves_archived_favorites_alone(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    device = bus.use(FakeMeshInterface(SELF_HEX))
    d_num = _favorited_archived_d(device)

    result = invoke(runner, ["peers", *PORT_ARGS, "--apply", "--json"], env)

    assert result.exit_code == 0
    assert ("unfav", d_num) not in device.peer_calls
    assert device.known_nodes[d_num]["isFavorite"] is True
    assert json.loads(result.stdout)["unfavorite"] == []


def test_a_dropped_unfavorite_fails_the_read_back(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    device = bus.use(FakeMeshInterface(SELF_HEX))
    _favorited_archived_d(device)
    device.drop_peer_writes = True

    result = invoke(runner, ["peers", *PORT_ARGS, "--apply", "--prune-archived", "--json"], env)

    assert result.exit_code == 5
    assert f"!{D_HEX}" in json.loads(result.stdout)["unconfirmed"]
    assert f"Sent, but the device still has !{D_HEX} favorited after reconnecting." in (
        result.stderr
    )
    (not_shown,) = [line for line in result.stderr.splitlines() if "does not show" in line]
    assert D_HEX not in not_shown


def _with_sync_peers(
    env: dict[str, str], write_template: Callable[..., Path], *, enabled: bool = True
) -> dict[str, str]:
    return {**env, "MESHPROVISION_TEMPLATE_PATH": str(write_template(sync_peers=enabled))}


def test_provision_syncs_peers_by_default(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    device = bus.use(FakeMeshInterface("a1b2c3d4"))

    result = invoke(runner, ["provision", *PORT_ARGS, "--yes"], env)

    assert result.exit_code == 0
    assert device.known_nodes[int(NodeId.parse(B_HEX))]["isFavorite"] is True


def test_provision_sync_peers_never_prunes_archived_favorites(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    device = bus.use(FakeMeshInterface("a1b2c3d4"))
    d_num = _favorited_archived_d(device)

    result = invoke(runner, ["provision", *PORT_ARGS, "--yes"], env)

    assert result.exit_code == 0
    assert ("unfav", d_num) not in device.peer_calls
    assert device.known_nodes[d_num]["isFavorite"] is True


def test_provision_leaves_the_contacts_alone_when_the_template_opts_out(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    fleet: Path,
    write_template: Callable[..., Path],
) -> None:
    device = bus.use(FakeMeshInterface("a1b2c3d4"))

    result = invoke(
        runner,
        ["provision", *PORT_ARGS, "--yes"],
        _with_sync_peers(env, write_template, enabled=False),
    )

    assert result.exit_code == 0
    assert device.peer_calls == []


def test_provision_dry_run_does_not_sync_peers(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    fleet: Path,
    write_template: Callable[..., Path],
) -> None:
    device = bus.use(FakeMeshInterface("a1b2c3d4"))

    result = invoke(
        runner,
        ["provision", *PORT_ARGS, "--dry-run"],
        _with_sync_peers(env, write_template),
    )

    assert result.exit_code == 0
    assert device.peer_calls == []


def test_a_failed_peer_sync_never_fails_provisioning(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    fleet: Path,
    write_template: Callable[..., Path],
) -> None:
    device = bus.use(FakeMeshInterface("a1b2c3d4"))
    device.fail_peer_writes = True

    result = invoke(
        runner, ["provision", *PORT_ARGS, "--yes"], _with_sync_peers(env, write_template)
    )

    assert result.exit_code == 0
    assert "Peer sync incomplete" in result.stderr
    assert "Database updated" in result.stderr


def test_a_peer_sync_that_raises_is_a_warning_not_a_provisioning_failure(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    fleet: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus.use(FakeMeshInterface("a1b2c3d4"))

    def _radio_gone(*_args: object, **_kwargs: object) -> object:
        raise OSError("radio went away")

    monkeypatch.setattr(peers_sync, "run_peers", _radio_gone)

    result = invoke(runner, ["provision", *PORT_ARGS, "--yes"], env)

    assert result.exit_code == 0
    assert "Peer sync failed (radio went away)" in result.stderr
    assert "mesh peers --apply" in result.stderr
    assert "Database updated" in result.stderr


def test_no_reconnect_provision_syncs_peers_without_a_bogus_read_back_failure(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """An in-place session cannot read back its own peer writes, so none is reported missing."""
    kp = keypair_factory()
    seed_db(
        nodes=[NodeRecord(node_id=SELF_HEX, management=ManagementMode.TEMPLATE), _node(B_HEX)],
        keys=[*KeyRecord.for_keypair(SELF_HEX, kp, origin=KeyOrigin.CAPTURED), _pub(B_HEX, KEY_B)],
    )
    device = bus.use(FakeMeshInterface(SELF_HEX))
    device.localNode.localConfig.security.public_key = kp.public
    device.localNode.localConfig.security.private_key = kp.private.reveal()

    result = invoke(runner, ["provision", *PORT_ARGS, "--yes", "--no-reconnect"], env)

    assert result.exit_code == 0, result.stderr
    assert device.known_nodes[int(NodeId.parse(B_HEX))]["isFavorite"] is True
    assert "Peer sync incomplete" not in result.stderr
