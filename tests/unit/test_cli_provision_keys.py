"""Tests for :func:`meshprovision.cli.provision_keys._capture_proven_private_key`.

The happy paths (a proven key recorded, a stale alias filled, no alias
private row ever created) are covered end to end in
``tests/e2e/test_e2e_provision.py``; these pin the two guards those runs
cannot reach: a live key that does not prove the recorded public key, and
an alias whose public key is different material.

Every assertion on a private-key row checks its ``origin`` before its
secret, and compares secrets as :class:`~meshprovision.crypto.redact.SecretBytes`,
so a failure never prints raw private-key bytes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import TYPE_CHECKING, Final

import pytest

from meshprovision.cli.provision_keys import _capture_proven_private_key
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.schema import KeyOrigin, KeyType
from meshprovision.nodeid import NodeId

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from meshprovision.crypto.keys import KeyPair
    from meshprovision.crypto.redact import SecretBytes

pytestmark = pytest.mark.unit

_NODE: Final = NodeId.from_hex("deadbe01")
_ALIAS: Final = "ADMIN2"
_NOW: Final = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture
def capture_db(empty_ods: Path) -> SimpleNamespace:
    """A stand-in for the CLI's ``DbSession``: the function only touches ``db.keys``."""
    session = OdsDatabase(empty_ods)
    session.load()
    return SimpleNamespace(keys=KeyRepository(session))


def _seed(keys: KeyRepository, owner: str, key_type: KeyType, raw: bytes | SecretBytes) -> None:
    keys.upsert(
        KeyRecord.from_material(owner, key_type, raw, origin=KeyOrigin.IMPORTED, created_ts=_NOW)
    )


def test_capture_proven_private_key_ignores_a_live_key_that_does_not_derive_the_recorded_public(
    capture_db: SimpleNamespace, keypair_factory: Callable[[], KeyPair]
) -> None:
    recorded, unrelated = keypair_factory(), keypair_factory()
    _seed(capture_db.keys, _NODE.hex, KeyType.ADMIN_PUBLIC, recorded.public)

    lines = _capture_proven_private_key(
        capture_db,  # type: ignore[arg-type]
        node_id=_NODE,
        live_private_key=unrelated.private,
        now=_NOW,
    )

    assert lines == ()
    assert capture_db.keys.find(f"{_NODE.hex}_priv") is None


def test_capture_proven_private_key_never_fills_an_alias_holding_different_public_material(
    capture_db: SimpleNamespace, keypair_factory: Callable[[], KeyPair]
) -> None:
    node_pair, other_admin, other_stale = keypair_factory(), keypair_factory(), keypair_factory()
    _seed(capture_db.keys, _NODE.hex, KeyType.ADMIN_PUBLIC, node_pair.public)
    _seed(capture_db.keys, _ALIAS, KeyType.ADMIN_PUBLIC, other_admin.public)
    _seed(capture_db.keys, _ALIAS, KeyType.ADMIN_PRIVATE, other_stale.private)

    lines = _capture_proven_private_key(
        capture_db,  # type: ignore[arg-type]
        node_id=_NODE,
        live_private_key=node_pair.private,
        now=_NOW,
    )

    alias_private = capture_db.keys.find(f"{_ALIAS}_priv")
    assert alias_private is not None
    assert alias_private.origin is KeyOrigin.IMPORTED
    assert alias_private.secret() == other_stale.private
    assert not any(_ALIAS in line for line in lines)
    assert len(lines) == 1
    assert "Recorded the device's private key for !deadbe01" in lines[0]
