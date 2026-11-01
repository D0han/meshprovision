"""Tests for :func:`meshprovision.cli.provision_keys.fresh_node_keypair` and its caller.

Firmware >= 2.8 renumbers a node to the CRC-32 of its public key, so a fresh
key whose derived id is reserved, or another database row's, is drawn again.
A random key almost never has such an id, so these tests forge public keys
with a chosen CRC-32 (:func:`_key_with_id`); the private half never matters
here, since only the public key's derived id is checked.
"""

from __future__ import annotations

import zlib
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import TYPE_CHECKING, Final

import pytest

from meshprovision.cli import provision_keys
from meshprovision.cli.provision_keys import (
    KEYGEN_ATTEMPTS,
    fresh_node_keypair,
    select_keypair,
    taken_node_ids,
)
from meshprovision.crypto.keys import KeyPair
from meshprovision.crypto.redact import SecretBytes
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository
from meshprovision.db.schema import KeyOrigin, KeyType
from meshprovision.errors import KeyMaterialError
from meshprovision.nodeid import BROADCAST_NODE_NUM, NodeId, key_derived_id

if TYPE_CHECKING:
    from collections.abc import Callable, Collection, Iterator

pytestmark = pytest.mark.unit

_PREFIX: Final[bytes] = bytes(range(28))


def _key_with_id(num: int) -> KeyPair:
    """Forge a keypair whose 32-byte public key has CRC-32 ``num``.

    CRC-32 over a fixed length is affine in the input bits, so the four
    trailing bytes that give any wanted CRC solve a 32x32 linear system
    over GF(2).
    """
    base = zlib.crc32(_PREFIX + bytes(4))
    columns = [zlib.crc32(_PREFIX + (1 << bit).to_bytes(4, "little")) ^ base for bit in range(32)]
    basis: dict[int, tuple[int, int]] = {}  # leading bit -> (column, input bits)
    for bit, column in enumerate(columns):
        mask = 1 << bit
        while column and column.bit_length() in basis:
            pivot_column, pivot_mask = basis[column.bit_length()]
            column, mask = column ^ pivot_column, mask ^ pivot_mask
        if column:
            basis[column.bit_length()] = (column, mask)
    want, tail = num ^ base, 0
    while want:
        pivot_column, pivot_mask = basis[want.bit_length()]
        want, tail = want ^ pivot_column, tail ^ pivot_mask
    public = _PREFIX + tail.to_bytes(4, "little")
    assert zlib.crc32(public) == num
    return KeyPair(private=SecretBytes(bytes(32)), public=public)


def _drawing(*keypairs: KeyPair) -> tuple[Callable[[], KeyPair], list[KeyPair]]:
    """A generator that hands out ``keypairs`` in order, and the list of those it drew."""
    drawn: list[KeyPair] = []
    pending: Iterator[KeyPair] = iter(keypairs)

    def generate() -> KeyPair:
        keypair = next(pending)
        drawn.append(keypair)
        return keypair

    return generate, drawn


@pytest.mark.parametrize("num", [0, 3, 0xDEADBE01, BROADCAST_NODE_NUM])
def test_the_forged_key_has_the_wanted_derived_id(num: int) -> None:
    assert key_derived_id(_key_with_id(num).public) == NodeId(num)


def test_a_usable_first_draw_is_returned_as_is() -> None:
    first = _key_with_id(0x12345678)
    generate, drawn = _drawing(first, _key_with_id(0x9ABCDEF0))

    assert fresh_node_keypair((), generate=generate) is first
    assert drawn == [first]


@pytest.mark.parametrize("reserved", [0, 1, 3, BROADCAST_NODE_NUM])
def test_a_key_whose_derived_id_is_reserved_is_drawn_again(reserved: int) -> None:
    usable = _key_with_id(4)
    generate, drawn = _drawing(_key_with_id(reserved), usable)

    assert fresh_node_keypair((), generate=generate) is usable
    assert len(drawn) == 2


def test_a_key_whose_derived_id_is_another_rows_is_drawn_again() -> None:
    usable = _key_with_id(0xCAFE0002)
    generate, drawn = _drawing(_key_with_id(0xCAFE0001), usable)

    assert fresh_node_keypair({NodeId(0xCAFE0001)}, generate=generate) is usable
    assert len(drawn) == 2


def test_no_usable_draw_in_every_attempt_is_an_error() -> None:
    taken = {NodeId(0xCAFE0001)}
    generate, drawn = _drawing(*(_key_with_id(0xCAFE0001) for _ in range(KEYGEN_ATTEMPTS + 1)))

    with pytest.raises(KeyMaterialError, match=f"{KEYGEN_ATTEMPTS} draws") as caught:
        fresh_node_keypair(taken, generate=generate)

    assert len(drawn) == KEYGEN_ATTEMPTS
    assert caught.value.reason == "no usable key-derived node id"


def test_keygen_attempts_is_sixteen() -> None:
    assert KEYGEN_ATTEMPTS == 16


def test_select_keypair_draws_a_fresh_key_avoiding_the_taken_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fresh = _key_with_id(0x12345678)
    seen: list[Collection[NodeId]] = []

    def spy(taken: Collection[NodeId]) -> KeyPair:
        seen.append(taken)
        return fresh

    monkeypatch.setattr(provision_keys, "fresh_node_keypair", spy)
    plan = SimpleNamespace(key_plan=SimpleNamespace(regenerate=True, adopt_device_key=False))
    taken = frozenset({NodeId(0xCAFE0001)})

    assert select_keypair(plan, SimpleNamespace(), taken=taken) is fresh  # type: ignore[arg-type]
    assert seen == [taken]


def test_taken_ids_are_every_row_and_node_key_owner_but_our_own(
    nodes: NodeRepository, keys: KeyRepository
) -> None:
    for node in ("deadbe01", "cafe0001"):
        nodes.upsert(NodeRecord(node_id=node, archived_at=None))
    nodes.upsert(NodeRecord(node_id="cafe0003", archived_at=datetime(2026, 1, 1, tzinfo=UTC)))
    for owner in ("cafe0002", "deadbe01", "ADMIN1"):
        keys.upsert(
            KeyRecord.from_material(
                owner, KeyType.ADMIN_PUBLIC, _key_with_id(7).public, origin=KeyOrigin.IMPORTED
            )
        )

    taken = taken_node_ids(nodes, keys, own=NodeId.from_hex("deadbe01"))

    assert taken == {NodeId.from_hex(n) for n in ("cafe0001", "cafe0002", "cafe0003")}
