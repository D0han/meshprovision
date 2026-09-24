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
    match_admin_key_refs,
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


_ALIASED = b"\x11" * 32
"""One public key deliberately filed under two Keys-sheet refs."""


@pytest.mark.parametrize(
    ("public_keys", "expected"),
    [
        pytest.param(
            {"deadbe01_pub": _ALIASED, "zzz_pub": _ALIASED},
            ("zzz_pub", "deadbe01_pub"),
            id="human-label-outranks-node-id-shape",
        ),
        pytest.param(
            {"deadbe01_pub": _ALIASED, "deadbe0_pub": _ALIASED},
            ("deadbe0_pub", "deadbe01_pub"),
            id="seven-hex-owner-is-not-node-id-shaped",
        ),
        pytest.param(
            {"ZULU_pub": _ALIASED, "ALPHA_pub": _ALIASED},
            ("ALPHA_pub", "ZULU_pub"),
            id="two-labels-tie-broken-lexicographically",
        ),
        pytest.param(
            {"ffffffff_pub": _ALIASED, "00000001_pub": _ALIASED},
            ("00000001_pub", "ffffffff_pub"),
            id="two-node-ids-tie-broken-lexicographically",
        ),
        pytest.param({"other_pub": b"\x22" * 32}, (), id="no-match"),
        pytest.param(
            {"observed-ab12cd34_pub": _ALIASED, "deadbe01_pub": _ALIASED},
            ("deadbe01_pub", "observed-ab12cd34_pub"),
            id="node-id-shape-outranks-an-observed-ref",
        ),
        pytest.param(
            {"observed-ab12cd34_pub": _ALIASED, "ADMIN1_pub": _ALIASED},
            ("ADMIN1_pub", "observed-ab12cd34_pub"),
            id="human-label-outranks-an-observed-ref",
        ),
        pytest.param(
            {"observed-ffffffff_pub": _ALIASED, "observed-00000001_pub": _ALIASED},
            ("observed-00000001_pub", "observed-ffffffff_pub"),
            id="two-observed-refs-tie-broken-lexicographically",
        ),
    ],
)
def test_match_admin_key_refs_orders_refs_preferred_first(
    public_keys: dict[str, bytes], expected: tuple[str, ...]
) -> None:
    """Regression test: PREFERRED order is not plain lexicographic order.

    ``mesh admin bootstrap --ref LABEL`` files one key under both
    ``<node_id>_pub`` and ``<LABEL>_pub``, and the first ref returned
    here becomes the displayed/persisted ``preferred_ref``. The
    human-labeled ref must win even when it sorts LAST lexicographically
    (``"zzz_pub"`` after ``"deadbe01_pub"``), and refs within each group
    must still fall back to lexicographic order.
    """
    assert match_admin_key_refs(_ALIASED, public_keys) == expected


def _live_with_security(security: detect.LiveSecurity) -> detect.LiveConfig:
    return detect.LiveConfig(node_id=NodeId.from_hex("deadbe01"), security=security)


def test_audit_live_admin_keys_rejects_malformed_length_material() -> None:
    live = _live_with_security(detect.LiveSecurity(admin_keys=(b"too-short",)))

    rejected = audit_live_admin_keys(live, known_bad=frozenset())

    assert rejected == frozenset({b"too-short"})


def test_audit_live_admin_keys_keeps_auditing_after_malformed_material(keypair: KeyPair) -> None:
    """Regression test: a malformed key must not end the audit loop.

    The malformed branch has to ``continue``, not ``break``: a device
    reporting a junk admin key followed by a genuinely blocklisted one
    would otherwise carry the blocklisted key straight through
    ``mesh provision`` unflagged.
    """
    live = _live_with_security(detect.LiveSecurity(admin_keys=(b"too-short", keypair.public)))

    rejected = audit_live_admin_keys(live, known_bad=frozenset({keypair.public}))

    assert rejected == frozenset({b"too-short", keypair.public})


def test_audit_live_admin_keys_uses_the_supplied_blocklist(keypair_factory) -> None:
    """The caller-supplied ``known_bad`` is authoritative, not the on-disk blocklist.

    ``mesh provision`` loads the blocklist once per run and threads it
    through; silently reloading it here would both break that contract
    and ignore an operator's in-memory additions.
    """
    listed, clean = keypair_factory(), keypair_factory()
    live = _live_with_security(detect.LiveSecurity(admin_keys=(listed.public, clean.public)))

    assert audit_live_admin_keys(live, known_bad=frozenset({listed.public})) == frozenset(
        {listed.public}
    )
    assert audit_live_admin_keys(live, known_bad=frozenset()) == frozenset()


def test_audit_node_key_malformed_private_key_is_reported_compromised(keypair: KeyPair) -> None:
    live = _live_with_security(
        detect.LiveSecurity(public_key=keypair.public, private_key=SecretBytes(b"too-short"))
    )

    compromised, reason = audit_node_key(live, known_bad=frozenset())

    assert compromised is True
    assert reason.startswith("malformed key material: ")


def test_audit_node_key_reports_a_blocklisted_device_keypair(keypair: KeyPair) -> None:
    """The real audit path: well-formed material that is nonetheless blocklisted.

    Distinct from the ``KeyMaterialError`` fallback above -- here
    :func:`weakkeys.audit_node` actually runs, so the returned reason
    must be the audit's own first critical finding.
    """
    live = _live_with_security(
        detect.LiveSecurity(public_key=keypair.public, private_key=keypair.private)
    )

    compromised, reason = audit_node_key(live, known_bad=frozenset({keypair.public}))

    assert compromised is True
    assert reason != "malformed key material"
    assert "blocklist" in reason


def test_audit_node_key_accepts_a_clean_device_keypair(keypair: KeyPair) -> None:
    live = _live_with_security(
        detect.LiveSecurity(public_key=keypair.public, private_key=keypair.private)
    )

    assert audit_node_key(live, known_bad=frozenset()) == (False, "")


def test_audit_node_key_logs_a_warning_severity_finding(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Regression test for Round 35's weakkey-drift review, Finding 3.

    audit_node_key reduced a full AuditResult to (compromised, first
    critical reason), silently discarding every warning-severity finding
    -- unlike every sibling audit path (resolve_admin_keys,
    adopt.build_adoption_report, db/verify.py), which all surface them.
    A structurally weak-but-not-critical key (low entropy) must now log,
    the same way resolve_admin_keys already does for the identical
    finding on an *admin* key.
    """
    live = _live_with_security(detect.LiveSecurity(public_key=_LOW_ENTROPY_PUBLIC))

    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        compromised, reason = audit_node_key(live, known_bad=frozenset())

    assert compromised is False
    assert reason == ""
    records = [r for r in caplog.records if r.getMessage().startswith("node key ")]
    assert [record.levelno for record in records] == [logging.WARNING]
    assert "deadbe01_pub" in records[0].getMessage()


@pytest.mark.parametrize(
    ("firmware", "expected_compromised", "expected_level", "expected_substring"),
    [
        pytest.param("", False, logging.WARNING, "could not be parsed", id="blank"),
        pytest.param("   ", False, logging.WARNING, "could not be parsed", id="whitespace-only"),
        pytest.param("garbage", False, logging.WARNING, "could not be parsed", id="garbage"),
        pytest.param("2.5.0", True, logging.ERROR, "CVE-2025-52464 window", id="2.5.0"),
        pytest.param("2.6.0", True, logging.ERROR, "CVE-2025-52464 window", id="2.6.0"),
        pytest.param("2.6.10", True, logging.ERROR, "CVE-2025-52464 window", id="2.6.10"),
        pytest.param("2.6.11", False, None, None, id="2.6.11"),
        pytest.param("2.7.11", False, None, None, id="2.7.11"),
    ],
)
def test_audit_node_key_firmware_matrix(
    keypair: KeyPair,
    caplog: pytest.LogCaptureFixture,
    firmware: str,
    expected_compromised: bool,
    expected_level: int | None,
    expected_substring: str | None,
) -> None:
    """Regression test for Finding #8: a blank firmware string must not be silently dropped.

    ``audit_node_key`` used to call ``weakkeys.audit_node`` with
    ``firmware_version=live.firmware_version or None``, collapsing a
    genuinely blank firmware string (``detect.read_live_config``'s value
    when the device reports no firmware metadata) into ``None``.
    ``weakkeys.audit_node`` treats the two differently: ``""`` is
    unparseable and produces a WARNING finding, while ``None`` skips the
    firmware check entirely. ``mesh adopt`` never did this collapsing and
    already warned correctly; ``mesh provision`` silently did not. This
    matrix exercises the parser boundary the fix restores, plus the
    unaffected CVE-2025-52464 window and clean-firmware cases on either
    side of it.
    """
    live = detect.LiveConfig(
        node_id=NodeId.from_hex("deadbe01"),
        firmware_version=firmware,
        security=detect.LiveSecurity(public_key=keypair.public, private_key=keypair.private),
    )

    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        compromised, reason = audit_node_key(live, known_bad=frozenset())

    assert compromised is expected_compromised
    records = [r for r in caplog.records if r.getMessage().startswith("node key ")]
    if expected_level is None:
        assert records == []
        assert reason == ""
    else:
        assert [record.levelno for record in records] == [expected_level]
        assert expected_substring is not None
        assert expected_substring in records[0].getMessage()
        if expected_level == logging.ERROR:
            assert expected_substring in reason
        else:
            assert reason == ""


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


def test_allocate_names_falls_back_when_the_long_pattern_cannot_render_the_short_index(
    nodes: NodeRepository,
) -> None:
    """The ``NamespaceExhaustedError`` branch: mismatched short/long capacities.

    ``MT{n}{n}`` over the alphabet ``"01"`` holds four names, ``L{n}``
    only two, so once the first two short names are taken the shared
    index (2) is outside the long pattern's namespace entirely and
    ``long_spec.render(index)`` raises. The fallback must search the
    long namespace independently from 0 rather than propagating the
    error or handing back a short-index-derived name.
    """
    template = load_template_text(
        'short_name_pattern: "MT{n}{n}"\n'
        'long_name_pattern: "L{n}"\n'
        'name_suffix_alphabet: "01"\n'
        "name_min_capacity: 1\n"
    )
    nodes.upsert(NodeRecord(node_id="00000000", short_name="MT00"))
    nodes.upsert(NodeRecord(node_id="00000001", short_name="MT01"))

    short, long = allocate_names(nodes, template, existing=None, rename=False)

    assert short == "MT10"
    assert long == "L0"
