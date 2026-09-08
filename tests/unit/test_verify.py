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
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.schema import KeyType
from meshprovision.db.verify import (
    DbProblemKind,
    ProblemSeverity,
    _check_permissions,
    _check_template_refs,
    _check_weak_keys,
    verify_database,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
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
    assert problems[0].message == "malformed key material"
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
