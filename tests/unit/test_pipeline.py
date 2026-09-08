"""Tests for meshprovision.provisioning.pipeline."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import pytest

from meshprovision.config.template import TemplateConfig, load_template_text
from meshprovision.crypto.redact import SecretBytes
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.schema import KeyType
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import detect
from meshprovision.provisioning.pipeline import (
    allocate_names,
    audit_live_admin_keys,
    audit_node_key,
    resolve_admin_keys,
    resolve_removed_admin_refs,
)

if TYPE_CHECKING:
    from pathlib import Path

    from meshprovision.crypto.keys import KeyPair

pytestmark = pytest.mark.unit

_LOGGER_NAME = "meshprovision.provisioning.pipeline"

_LOW_ENTROPY_PUBLIC = bytes([0x0F, 0x33, 0x55, 0x66]) * 8
"""Four distinct byte values -- trips the low-entropy check at warning severity only."""


@pytest.fixture
def keys(empty_ods: Path) -> KeyRepository:
    db = OdsDatabase(empty_ods)
    db.load()
    return KeyRepository(db)


@pytest.fixture
def nodes(empty_ods: Path) -> NodeRepository:
    db = OdsDatabase(empty_ods)
    db.load()
    return NodeRepository(db)


def _naming_template() -> TemplateConfig:
    return load_template_text(
        'short_name_pattern: "MT{n}{n}"\nlong_name_pattern: "Meshtastic {n}{n}"\n'
    )


def _template_with_admin(*refs: str) -> TemplateConfig:
    return load_template_text("version: 1\n").model_copy(update={"admin_nodes": refs})


def _audit_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.getMessage().startswith("admin key ")]


def test_soft_audit_finding_logs_a_warning(
    keys: KeyRepository, caplog: pytest.LogCaptureFixture
) -> None:
    keys.upsert(KeyRecord.from_material("ADMIN1", KeyType.ADMIN_PUBLIC, _LOW_ENTROPY_PUBLIC))

    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        resolved = resolve_admin_keys(keys, _template_with_admin("ADMIN1"), known_bad=frozenset())

    assert resolved[0].audit_ok is True
    records = _audit_records(caplog)
    assert [record.levelno for record in records] == [logging.WARNING]
    assert "ADMIN1_pub" in records[0].getMessage()


def test_compromised_admin_key_logs_an_error(
    keys: KeyRepository, keypair: KeyPair, caplog: pytest.LogCaptureFixture
) -> None:
    keys.upsert(KeyRecord.from_material("ADMIN1", KeyType.ADMIN_PUBLIC, keypair.public))

    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        resolved = resolve_admin_keys(
            keys, _template_with_admin("ADMIN1"), known_bad=frozenset({keypair.public})
        )

    assert resolved[0].audit_ok is False
    records = _audit_records(caplog)
    assert [record.levelno for record in records] == [logging.ERROR]
    assert "[critical]" in records[0].getMessage()


def test_resolve_admin_keys_reports_a_private_key_mismatch(
    keys: KeyRepository, keypair_factory, caplog: pytest.LogCaptureFixture
) -> None:
    kp_a, kp_b = keypair_factory(), keypair_factory()
    pub, _ = KeyRecord.for_keypair("ADMIN1", kp_a)
    _, mismatched_priv = KeyRecord.for_keypair("ADMIN1", kp_b)
    keys.upsert(pub)
    keys.upsert(mismatched_priv)

    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        resolved = resolve_admin_keys(keys, _template_with_admin("ADMIN1"), known_bad=frozenset())

    assert resolved[0].has_private is False
    assert resolved[0].private_mismatch is True
    assert any("does not derive" in record.getMessage() for record in caplog.records)


def _live_with_security(security: detect.LiveSecurity) -> detect.LiveConfig:
    return detect.LiveConfig(node_id=NodeId.from_hex("deadbe01"), security=security)


def test_audit_live_admin_keys_rejects_malformed_length_material() -> None:
    live = _live_with_security(detect.LiveSecurity(admin_keys=(b"too-short",)))

    rejected = audit_live_admin_keys(live, known_bad=frozenset())

    assert rejected == frozenset({b"too-short"})


def test_audit_node_key_malformed_private_key_is_reported_compromised(keypair: KeyPair) -> None:
    live = _live_with_security(
        detect.LiveSecurity(public_key=keypair.public, private_key=SecretBytes(b"too-short"))
    )

    compromised, reason = audit_node_key(live, known_bad=frozenset())

    assert compromised is True
    assert reason == "malformed key material"


_MAP = {"A_pub": b"a" * 32, "B_pub": b"b" * 32}


@pytest.mark.parametrize(
    ("record", "rejected", "expected"),
    [
        pytest.param(None, frozenset({b"a" * 32}), (), id="no-record"),
        pytest.param(
            NodeRecord(node_id="deadbe01", authorized_admin_keys=("A_pub", "B_pub")),
            frozenset(),
            (),
            id="nothing-rejected",
        ),
        pytest.param(
            NodeRecord(node_id="deadbe01", authorized_admin_keys=("A_pub", "B_pub")),
            frozenset({b"b" * 32}),
            ("B_pub",),
            id="one-of-two-rejected",
        ),
        pytest.param(
            NodeRecord(node_id="deadbe01", authorized_admin_keys=("A_pub", "GHOST_pub")),
            frozenset({b"a" * 32}),
            ("A_pub",),
            id="unknown-ref-skipped",
        ),
        pytest.param(
            NodeRecord(node_id="deadbe01", authorized_admin_keys=("B_pub", "A_pub")),
            frozenset({b"a" * 32, b"b" * 32}),
            ("B_pub", "A_pub"),
            id="both-rejected-order-preserved",
        ),
    ],
)
def test_resolve_removed_admin_refs(
    record: NodeRecord | None, rejected: frozenset[bytes], expected: tuple[str, ...]
) -> None:
    assert resolve_removed_admin_refs(record, _MAP, rejected) == expected


def test_allocate_names_returns_none_when_existing_and_not_renaming(nodes: NodeRepository) -> None:
    existing = NodeRecord(node_id="deadbe01", short_name="MT00", long_name="Meshtastic 00")
    assert allocate_names(nodes, _naming_template(), existing=existing, rename=False) == (
        None,
        None,
    )


def test_allocate_names_picks_same_index_for_short_and_long_when_free(
    nodes: NodeRepository,
) -> None:
    short, long = allocate_names(nodes, _naming_template(), existing=None, rename=False)
    assert short == "MT00"
    assert long == "Meshtastic 00"


def test_allocate_names_avoids_long_name_collision_when_namespaces_diverge(
    nodes: NodeRepository,
) -> None:
    """Regression test: the short and long namespaces are searched independently.

    A node whose long_name was recorded out of lockstep with the current
    pattern's index scheme (older template, hand-edited row, imported
    legacy record) must not cause a fresh allocation to hand out a
    long_name that's already in use, even though the short_name at that
    same index is free.
    """
    nodes.upsert(NodeRecord(node_id="00000001", short_name="ZZ99", long_name="Meshtastic 00"))

    short, long = allocate_names(nodes, _naming_template(), existing=None, rename=False)

    assert short == "MT00"
    assert long != "Meshtastic 00"
    assert long.casefold() not in {n.casefold() for n in nodes.used_long_names()}


def test_allocate_names_finds_a_free_long_name_below_the_short_names_index(
    nodes: NodeRepository,
) -> None:
    """The long-name fallback search must cover the WHOLE namespace, not just index+.

    A prior bug started the fallback search at the short name's own
    index (``start=index``) rather than 0, so a free long name sitting
    at a LOWER index than the short name's index could never be found --
    even though the sibling fallback branch just above it (when
    render(index) itself raises) correctly searches from 0.
    """
    for i in range(5):
        nodes.upsert(NodeRecord(node_id=f"0000000{i}", short_name=f"MT0{i}", long_name="unused"))
    for i in range(20):
        if i == 2:
            continue
        nodes.upsert(
            NodeRecord(
                node_id=f"1000000{i}" if i < 10 else f"100000{i}", long_name=f"Meshtastic 0{i}"
            )
        )

    short, long = allocate_names(nodes, _naming_template(), existing=None, rename=False)

    assert short == "MT05"
    assert long == "Meshtastic 02"
