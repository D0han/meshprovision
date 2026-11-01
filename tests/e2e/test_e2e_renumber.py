"""Firmware >= 2.8 key-derived node ids, end to end.

Firmware 2.8 renumbers a node to the CRC-32 of its public key. These tests
cover what ``mesh provision`` does about it: a fresh key never derives an id
the database already uses.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from meshprovision.cli import provision_keys
from meshprovision.crypto.keys import KeyPair, generate_keypair
from meshprovision.db.keys import KeyRecord
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import KeyOrigin, KeyType, ManagementMode
from meshprovision.nodeid import NodeId
from tests.e2e.conftest import FakeMeshInterface, invoke

if TYPE_CHECKING:
    from collections.abc import Callable, Collection
    from pathlib import Path

    from click.testing import CliRunner

    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e


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
