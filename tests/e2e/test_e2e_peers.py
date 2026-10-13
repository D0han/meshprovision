"""``mesh peers`` and the ``sync_peers`` provisioning step against a fake device NodeDB."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from meshprovision.db.keys import KeyRecord
from meshprovision.db.node_record import NodeRecord
from meshprovision.db.schema import KeyOrigin, KeyType
from meshprovision.nodeid import NodeId
from tests.conftest import BASE64_KEY_RE
from tests.e2e.conftest import FakeMeshInterface, db_fingerprint, invoke

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from click.testing import CliRunner

    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e

SELF_HEX = "deadbe01"
B_HEX = "b0000002"
C_HEX = "c0000003"
D_HEX = "d0000004"
KEY_SELF = bytes([1]) * 32
KEY_B = bytes([2]) * 32
OTHER_KEY = bytes([9]) * 32
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
    assert B_HEX in result.stderr
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
    assert db_fingerprint(fleet) == before

    calls_after_first = list(device.peer_calls)
    second = invoke(runner, ["peers", *PORT_ARGS, "--apply"], env)

    assert second.exit_code == 0
    assert "in sync" in second.stderr
    assert device.peer_calls == calls_after_first


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


def test_a_write_the_device_silently_drops_fails_the_read_back(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    device = bus.use(FakeMeshInterface(SELF_HEX))
    device.drop_peer_writes = True

    result = invoke(runner, ["peers", *PORT_ARGS, "--apply"], env)

    assert result.exit_code == 5
    assert "does not show" in result.stderr
    assert B_HEX in result.stderr


def test_a_rejected_write_is_reported_and_fails_the_run(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, fleet: Path
) -> None:
    device = bus.use(FakeMeshInterface(SELF_HEX))
    device.fail_peer_writes = True

    result = invoke(runner, ["peers", *PORT_ARGS, "--apply"], env)

    assert result.exit_code == 5
    assert "simulated contact write failure" in result.stderr


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
    assert document["unconfirmed"] == []
    assert not BASE64_KEY_RE.search(result.stdout + result.stderr)


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
