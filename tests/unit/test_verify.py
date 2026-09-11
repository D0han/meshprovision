"""Tests for meshprovision.db.verify's compute half.

Exercises verify_database (and, for the one branch that can't be
reached through a real ODS round-trip, the private _check_weak_keys
helper directly) independent of the CLI -- mirroring
tests/unit/test_admin_custody.py's pattern for the sibling
provisioning/admin_custody.py extraction.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest
from pydantic import SecretStr

from meshprovision.config.template import load_template_text
from meshprovision.crypto.keys import encode_key
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.schema import KeyType
from meshprovision.db.verify import (
    DbProblemKind,
    ProblemSeverity,
    _check_admin_key_mismatch,
    _check_duplicate_keys,
    _check_permissions,
    _check_template_refs,
    _check_unregistered_duplicate_keys,
    _check_unresolved_admin_refs,
    _check_weak_keys,
    verify_database,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    from meshprovision.crypto.keys import KeyPair

pytestmark = pytest.mark.unit


@pytest.fixture
def db(empty_ods: Path) -> OdsDatabase:
    session = OdsDatabase(empty_ods)
    session.load()
    return session


@pytest.fixture
def nodes(db: OdsDatabase) -> NodeRepository:
    return NodeRepository(db)


@pytest.fixture
def keys(db: OdsDatabase) -> KeyRepository:
    return KeyRepository(db)


@pytest.fixture
def template():
    return load_template_text("version: 1\n")


class _KeysAllOnly:
    """A minimal KeyRepository double exposing only .all().

    For testing _check_weak_keys in isolation from real Keys-sheet row
    validation.
    """

    def __init__(self, records: Sequence[KeyRecord]) -> None:
        self._records = tuple(records)

    def all(self) -> tuple[KeyRecord, ...]:
        return self._records


def test_check_weak_keys_malformed_material_reports_critical_problem() -> None:
    """Report malformed key material rather than crash or skip it silently.

    A KeyRecord whose key_value is corrupted enough that .material()
    itself raises (never reachable through a real ODS load, since
    KeyRecord's own field validator already rejects malformed base64 at
    construction time -- this is the module's own documented "should not
    happen... re-checked defensively" case) must still be reported.
    """
    malformed = KeyRecord.model_construct(
        key_ref="ADMIN1_pub",
        owner_node_id="ADMIN1",
        key_type=KeyType.ADMIN_PUBLIC,
        key_value=SecretStr("not-valid-base64!!!"),
        created_ts=None,
    )

    problems = _check_weak_keys(_KeysAllOnly([malformed]), known_bad=frozenset())

    assert len(problems) == 1
    assert problems[0].kind == DbProblemKind.WEAK_KEY
    assert problems[0].severity == ProblemSeverity.CRITICAL
    assert problems[0].message.startswith("malformed key material: ")
    assert problems[0].ref == "ADMIN1_pub"


def test_verify_database_template_error_adds_unavailable_problem(
    nodes: NodeRepository, keys: KeyRepository, db: OdsDatabase
) -> None:
    report = verify_database(
        path=db.path,
        warnings=(),
        nodes=nodes,
        keys=keys,
        template=None,
        known_bad=frozenset(),
        template_error="boom: could not parse template.yaml",
    )

    kinds = [p.kind for p in report.problems]
    assert DbProblemKind.TEMPLATE_UNAVAILABLE in kinds


def test_verify_database_no_template_configured_adds_no_unavailable_problem(
    nodes: NodeRepository, keys: KeyRepository, db: OdsDatabase
) -> None:
    """No template configured at all must not report as a failed load.

    template=None with template_error=None means "no template configured
    at all", not "failed to load".
    """
    report = verify_database(
        path=db.path,
        warnings=(),
        nodes=nodes,
        keys=keys,
        template=None,
        known_bad=frozenset(),
        template_error=None,
    )

    kinds = [p.kind for p in report.problems]
    assert DbProblemKind.TEMPLATE_UNAVAILABLE not in kinds


@pytest.mark.skipif(os.name != "posix", reason="permission bits are not meaningful on this OS")
def test_check_permissions_flags_a_group_or_world_readable_file(tmp_path: Path) -> None:
    path = tmp_path / "nodes_db.ods"
    path.write_bytes(b"x")
    path.chmod(0o644)

    problems = _check_permissions(path)

    assert len(problems) == 1
    assert problems[0].kind == DbProblemKind.INSECURE_PERMISSIONS
    assert problems[0].severity == ProblemSeverity.WARNING


@pytest.mark.skipif(os.name != "posix", reason="permission bits are not meaningful on this OS")
def test_check_permissions_accepts_an_owner_only_file(tmp_path: Path) -> None:
    path = tmp_path / "nodes_db.ods"
    path.write_bytes(b"x")
    path.chmod(0o600)

    assert _check_permissions(path) == []


def test_check_template_refs_resolved_entry_produces_no_problem(
    keys: KeyRepository, template, db: OdsDatabase, keypair: KeyPair
) -> None:
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1",)})
    pub, priv = KeyRecord.for_keypair("ADMIN1", keypair)
    keys.upsert(pub)
    keys.upsert(priv)

    assert _check_template_refs(keys, template2) == []


def test_check_template_refs_unresolved_entry_produces_a_problem(
    keys: KeyRepository, template
) -> None:
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1",)})

    problems = _check_template_refs(keys, template2)

    assert len(problems) == 1
    assert problems[0].kind == DbProblemKind.UNRESOLVED_TEMPLATE_REF
    assert problems[0].severity == ProblemSeverity.ERROR
    assert problems[0].ref == "ADMIN1"


def test_check_duplicate_keys_two_distinct_nodes_sharing_a_key_is_critical(
    keys: KeyRepository, keypair: KeyPair
) -> None:
    """Two real devices holding the same public key is the CVE-2025-52464 signature."""
    keys.upsert(KeyRecord.from_material("deadbe01", KeyType.ADMIN_PUBLIC, keypair.public))
    keys.upsert(KeyRecord.from_material("deadbe02", KeyType.ADMIN_PUBLIC, keypair.public))

    problems = _check_duplicate_keys(keys)

    assert len(problems) == 1
    assert problems[0].kind == DbProblemKind.DUPLICATE_PUBLIC_KEY
    assert problems[0].severity == ProblemSeverity.CRITICAL
    assert problems[0].ref == "deadbe01_pub,deadbe02_pub"
    assert "deadbe01, deadbe02" in problems[0].message


def test_check_duplicate_keys_node_plus_its_own_alias_is_only_a_warning(
    keys: KeyRepository, keypair: KeyPair
) -> None:
    """`mesh admin bootstrap --ref LABEL` deliberately files one key under two refs.

    One physical node's key filed under both ``<node_id>_pub`` and
    ``<LABEL>_pub`` is the expected, documented shape -- an
    informational alias warning, never the critical clone finding.
    """
    keys.upsert(KeyRecord.from_material("deadbe01", KeyType.ADMIN_PUBLIC, keypair.public))
    keys.upsert(KeyRecord.from_material("ADMIN1", KeyType.ADMIN_PUBLIC, keypair.public))

    problems = _check_duplicate_keys(keys)

    assert len(problems) == 1
    assert problems[0].kind == DbProblemKind.ALIAS_PUBLIC_KEY
    assert problems[0].severity == ProblemSeverity.WARNING


def test_check_duplicate_keys_two_hex_shaped_labels_are_only_a_warning(
    keys: KeyRepository, keypair: KeyPair
) -> None:
    """A short hex-looking template label is not a node id.

    ``NodeId.try_parse`` accepts a 1-7 character all-hex string, so
    labels like ``"cafe"``/``"face"`` parse -- but neither round-trips to
    its own canonical ``NodeId.hex`` form (``"0000cafe"``), so neither
    counts as a real device and the group stays a warning.
    """
    keys.upsert(KeyRecord.from_material("cafe", KeyType.ADMIN_PUBLIC, keypair.public))
    keys.upsert(KeyRecord.from_material("face", KeyType.ADMIN_PUBLIC, keypair.public))

    problems = _check_duplicate_keys(keys)

    assert len(problems) == 1
    assert problems[0].kind == DbProblemKind.ALIAS_PUBLIC_KEY
    assert problems[0].severity == ProblemSeverity.WARNING


def test_check_duplicate_keys_distinct_keys_produce_no_problem(
    keys: KeyRepository, keypair_factory: Callable[[], KeyPair]
) -> None:
    keys.upsert(KeyRecord.from_material("deadbe01", KeyType.ADMIN_PUBLIC, keypair_factory().public))
    keys.upsert(KeyRecord.from_material("deadbe02", KeyType.ADMIN_PUBLIC, keypair_factory().public))

    assert _check_duplicate_keys(keys) == []


def test_check_admin_key_mismatch_flags_a_private_key_that_does_not_derive_its_public(
    keys: KeyRepository, keypair_factory: Callable[[], KeyPair]
) -> None:
    """A `_priv` row holding unrelated bytes means corruption or a partial restore."""
    keys.upsert(KeyRecord.from_material("ADMIN1", KeyType.ADMIN_PUBLIC, keypair_factory().public))
    keys.upsert(KeyRecord.from_material("ADMIN1", KeyType.ADMIN_PRIVATE, keypair_factory().private))

    problems = _check_admin_key_mismatch(keys)

    assert len(problems) == 1
    assert problems[0].kind == DbProblemKind.ADMIN_KEY_MISMATCH
    assert problems[0].severity == ProblemSeverity.CRITICAL
    assert problems[0].ref == "ADMIN1_priv"


def test_check_admin_key_mismatch_accepts_a_consistent_pair(
    keys: KeyRepository, keypair: KeyPair
) -> None:
    pub, priv = KeyRecord.for_keypair("ADMIN1", keypair)
    keys.upsert(pub)
    keys.upsert(priv)

    assert _check_admin_key_mismatch(keys) == []


def test_check_admin_key_mismatch_skips_a_private_key_with_no_public_row(
    keys: KeyRepository, keypair: KeyPair
) -> None:
    """With no public row there is nothing to derive against, so nothing to report."""
    keys.upsert(KeyRecord.from_material("ADMIN1", KeyType.ADMIN_PRIVATE, keypair.private))

    assert _check_admin_key_mismatch(keys) == []


def test_check_unresolved_admin_refs_flags_a_ref_absent_from_the_keys_sheet(
    nodes: NodeRepository, keys: KeyRepository
) -> None:
    nodes.upsert(NodeRecord(node_id="deadbe01", authorized_admin_keys=("ADMIN1_pub",)))

    problems = _check_unresolved_admin_refs(nodes, keys)

    assert len(problems) == 1
    assert problems[0].kind == DbProblemKind.UNRESOLVED_ADMIN_REF
    assert problems[0].severity == ProblemSeverity.ERROR
    assert problems[0].ref == "deadbe01"
    assert "ADMIN1_pub" in problems[0].message


def test_check_unresolved_admin_refs_accepts_a_resolvable_ref(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    keys.upsert(KeyRecord.from_material("ADMIN1", KeyType.ADMIN_PUBLIC, keypair.public))
    nodes.upsert(NodeRecord(node_id="deadbe01", authorized_admin_keys=("ADMIN1_pub",)))

    assert _check_unresolved_admin_refs(nodes, keys) == []


def test_check_unregistered_duplicate_keys_flags_two_never_imported_clones(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    """Two adopted devices sharing an admin key neither of which was ever imported.

    The exact CVE-2025-52464 scenario the Keys-sheet pass cannot see:
    with no `mesh admin import` for either device there is no Keys sheet
    row to compare, so only the Nodes-sheet unregistered material match
    catches it.
    """
    material = encode_key(keypair.public)
    nodes.upsert(NodeRecord(node_id="deadbe01", unregistered_admin_keys=(material,)))
    nodes.upsert(NodeRecord(node_id="deadbe02", unregistered_admin_keys=(material,)))

    problems = _check_unregistered_duplicate_keys(nodes, keys)

    assert len(problems) == 1
    assert problems[0].kind == DbProblemKind.DUPLICATE_PUBLIC_KEY
    assert problems[0].severity == ProblemSeverity.CRITICAL
    assert problems[0].sheet == "Nodes"
    assert problems[0].ref == "deadbe01,deadbe02"
    assert "never-imported" in problems[0].message


def test_check_unregistered_duplicate_keys_flags_a_clone_of_another_nodes_registered_key(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    """One device's never-imported key matching another device's registered key."""
    keys.upsert(KeyRecord.from_material("ADMIN1", KeyType.ADMIN_PUBLIC, keypair.public))
    nodes.upsert(NodeRecord(node_id="deadbe01", authorized_admin_keys=("ADMIN1_pub",)))
    nodes.upsert(
        NodeRecord(node_id="deadbe02", unregistered_admin_keys=(encode_key(keypair.public),))
    )

    problems = _check_unregistered_duplicate_keys(nodes, keys)

    assert len(problems) == 1
    assert problems[0].kind == DbProblemKind.DUPLICATE_PUBLIC_KEY
    assert problems[0].severity == ProblemSeverity.CRITICAL
    assert problems[0].ref == "deadbe01,deadbe02"
    assert "authorized on node deadbe01" in problems[0].message


def test_check_unregistered_duplicate_keys_ignores_a_nodes_own_registered_key(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    """One node holding the same key both registered and unregistered is not a clone."""
    keys.upsert(KeyRecord.from_material("ADMIN1", KeyType.ADMIN_PUBLIC, keypair.public))
    nodes.upsert(
        NodeRecord(
            node_id="deadbe01",
            authorized_admin_keys=("ADMIN1_pub",),
            unregistered_admin_keys=(encode_key(keypair.public),),
        )
    )
    nodes.upsert(NodeRecord(node_id="deadbe02"))

    assert _check_unregistered_duplicate_keys(nodes, keys) == []


def test_check_unregistered_duplicate_keys_accepts_distinct_unregistered_keys(
    nodes: NodeRepository, keys: KeyRepository, keypair_factory: Callable[[], KeyPair]
) -> None:
    nodes.upsert(
        NodeRecord(
            node_id="deadbe01", unregistered_admin_keys=(encode_key(keypair_factory().public),)
        )
    )
    nodes.upsert(
        NodeRecord(
            node_id="deadbe02", unregistered_admin_keys=(encode_key(keypair_factory().public),)
        )
    )

    assert _check_unregistered_duplicate_keys(nodes, keys) == []


def test_check_unregistered_duplicate_keys_dedupes_per_pair_across_a_three_node_cluster(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    """Three devices sharing one never-imported key report all three pairs, once each.

    Regression guard for the ``marker = (*pair, tier, fingerprint)`` dedup
    key: if a mutant collapsed that key to drop the pair (e.g. just
    ``(tier, fingerprint)``), every pair beyond the first would look
    "already seen" and only one of the three genuinely distinct clone
    pairs would be reported.
    """
    material = encode_key(keypair.public)
    for node_id in ("deadbe01", "deadbe02", "deadbe03"):
        nodes.upsert(NodeRecord(node_id=node_id, unregistered_admin_keys=(material,)))

    problems = _check_unregistered_duplicate_keys(nodes, keys)

    assert {problem.ref for problem in problems} == {
        "deadbe01,deadbe02",
        "deadbe01,deadbe03",
        "deadbe02,deadbe03",
    }


def test_check_unregistered_duplicate_keys_checks_every_material_on_a_multi_key_node(
    nodes: NodeRepository, keys: KeyRepository, keypair_factory: Callable[[], KeyPair]
) -> None:
    """A node with two distinct unregistered keys, each cloned on a different other node.

    Regression guard for the per-material ``else: continue`` on the
    non-match branch: node A holds material X (first) then Y (second);
    node B clones X (unregistered) and node C clones Y (registered, so
    C itself contributes no unregistered material and can't rediscover
    the pair from the reverse direction -- that would mask the bug via
    the same dedup collision seen in the elif test above). For
    ``other=C``, X fails to match before Y succeeds, so a
    ``continue``-to-``break`` regression on the non-match branch would
    stop the loop at X and silently drop the genuine Y/C clone -- with
    nothing to rediscover it, the pair would vanish outright rather
    than just being deduped.
    """
    keypair_y = keypair_factory()
    material_x = encode_key(keypair_factory().public)
    material_y = encode_key(keypair_y.public)
    keys.upsert(KeyRecord.from_material("ADMINC", KeyType.ADMIN_PUBLIC, keypair_y.public))
    nodes.upsert(NodeRecord(node_id="deadbe0a", unregistered_admin_keys=(material_x, material_y)))
    nodes.upsert(NodeRecord(node_id="deadbe0b", unregistered_admin_keys=(material_x,)))
    nodes.upsert(NodeRecord(node_id="deadbe0c", authorized_admin_keys=("ADMINC_pub",)))

    problems = _check_unregistered_duplicate_keys(nodes, keys)

    assert {problem.ref for problem in problems} == {"deadbe0a,deadbe0b", "deadbe0a,deadbe0c"}


def test_check_unregistered_duplicate_keys_prefers_registered_tier_when_both_match(
    nodes: NodeRepository, keys: KeyRepository, keypair: KeyPair
) -> None:
    """When another node's material is both registered and unregistered, the elif picks registered.

    Regression guard for the ``elif`` precedence between the two tiers:
    ``deadbe01`` here authorizes the shared key as a registered admin key
    *and* separately lists it (e.g. from a stale prior adopt) as an
    unregistered material, so checking from ``deadbe02``'s side must
    resolve to the registered-tier message, not the unregistered one.

    Two problems are expected, not one: this same setup also makes
    ``deadbe01`` a valid *record* in its own right (it holds the
    material unregistered too), so it independently discovers
    ``deadbe02``'s copy via the unregistered/unregistered tier -- a
    real, distinct signal, not a duplicate of the first. Collapsing
    the ``elif`` to a second unconditional ``if`` doesn't add a third
    problem (the single post-branch ``problems.append`` means the
    second branch only *overwrites* ``tier``/``message`` when both
    match); instead it silently flips ``deadbe02``'s finding from
    registered to unregistered, whose marker then collides with the
    other direction's already-``seen`` marker and gets deduped away
    entirely -- dropping the total from 2 to 1 while also losing the
    "authorized on node deadbe01" message. Both effects are asserted
    below so the test fails loudly either way.
    """
    material = encode_key(keypair.public)
    keys.upsert(KeyRecord.from_material("ADMIN1", KeyType.ADMIN_PUBLIC, keypair.public))
    nodes.upsert(
        NodeRecord(
            node_id="deadbe01",
            authorized_admin_keys=("ADMIN1_pub",),
            unregistered_admin_keys=(material,),
        )
    )
    nodes.upsert(NodeRecord(node_id="deadbe02", unregistered_admin_keys=(material,)))

    problems = _check_unregistered_duplicate_keys(nodes, keys)

    assert len(problems) == 2
    assert any("authorized on node deadbe01" in problem.message for problem in problems)


def test_verify_database_reports_an_unregistered_clone_pair_as_critical(
    nodes: NodeRepository, keys: KeyRepository, template, db: OdsDatabase, keypair: KeyPair
) -> None:
    """The unregistered cross-check is actually wired into verify_database."""
    material = encode_key(keypair.public)
    nodes.upsert(NodeRecord(node_id="deadbe01", unregistered_admin_keys=(material,)))
    nodes.upsert(NodeRecord(node_id="deadbe02", unregistered_admin_keys=(material,)))

    report = verify_database(
        path=db.path,
        warnings=(),
        nodes=nodes,
        keys=keys,
        template=template,
        known_bad=frozenset(),
    )

    assert report.has_critical
    duplicates = [p for p in report.problems if p.kind == DbProblemKind.DUPLICATE_PUBLIC_KEY]
    assert len(duplicates) == 1
    assert duplicates[0].sheet == "Nodes"


def test_verify_database_reports_node_count_and_key_count(
    nodes: NodeRepository, keys: KeyRepository, template, db: OdsDatabase, keypair: KeyPair
) -> None:
    nodes.upsert(NodeRecord(node_id="deadbe01"))
    pub, priv = KeyRecord.for_keypair("deadbe01", keypair)
    keys.upsert(pub)
    keys.upsert(priv)

    report = verify_database(
        path=db.path,
        warnings=(),
        nodes=nodes,
        keys=keys,
        template=template,
        known_bad=frozenset(),
    )

    assert report.node_count == 1
    assert report.key_count == 2
