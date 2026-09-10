"""Tests for meshprovision.provisioning.admin_custody's compute half.

Exercises `collect_admins` directly against a `NodeRepository`/
`KeyRepository` pair, independent of the CLI -- this is exactly the
"focused unit test that doesn't go through Click" the module's own
docstring says the extraction out of cli/admin.py was meant to enable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from meshprovision.config.template import load_template_text
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.schema import KeyType
from meshprovision.provisioning.admin_custody import collect_admins

if TYPE_CHECKING:
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


def test_collect_admins_discovers_a_fleet_admin_not_in_template(
    nodes: NodeRepository, keys: KeyRepository, template, keypair: KeyPair
) -> None:
    """A fleet-authorized admin outside the template must be discovered.

    An ADMIN_PUBLIC key whose owner ref isn't in template.admin_nodes,
    but whose key_ref IS authorized on some node, must still be
    discovered -- this is collect_admins' headline fleet-discovery
    feature, previously untested at any level.
    """
    node = NodeRecord(node_id="deadbe01", authorized_admin_keys=("EXTRA1_pub",))
    nodes.upsert(node)
    pub, priv = KeyRecord.for_keypair("EXTRA1", keypair)
    keys.upsert(pub)
    keys.upsert(priv)

    summaries = collect_admins(nodes, keys, template, known_bad=frozenset())

    extra = next((s for s in summaries if s.ref == "EXTRA1"), None)
    assert extra is not None
    assert extra.in_template is False
    assert extra.present is True
    assert extra.authorized_on == ("deadbe01",)


def test_collect_admins_ignores_a_fleet_key_authorized_nowhere(
    nodes: NodeRepository, keys: KeyRepository, template, keypair: KeyPair
) -> None:
    """An unauthorized fleet key must NOT be discovered.

    An ADMIN_PUBLIC key that exists in the Keys sheet but is not
    authorized on any node's authorized_admin_keys must NOT be
    fleet-discovered -- only presence in the Keys sheet is not enough.
    """
    node = NodeRecord(node_id="deadbe01", authorized_admin_keys=())
    nodes.upsert(node)
    pub, priv = KeyRecord.for_keypair("UNUSED1", keypair)
    keys.upsert(pub)
    keys.upsert(priv)

    summaries = collect_admins(nodes, keys, template, known_bad=frozenset())

    assert not any(s.ref == "UNUSED1" for s in summaries)


def test_collect_admins_does_not_double_count_a_template_admin_via_fleet_discovery(
    nodes: NodeRepository, keys: KeyRepository, template, keypair: KeyPair
) -> None:
    """A template admin also fleet-authorized must not be double-counted.

    A template-listed admin ref that is ALSO authorized on a node's
    authorized_admin_keys must appear exactly once -- the fleet-discovery
    loop's `if owner in template_set: continue` dedup guard.
    """
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1",)})
    node = NodeRecord(node_id="deadbe01", authorized_admin_keys=("ADMIN1_pub",))
    nodes.upsert(node)
    pub, priv = KeyRecord.for_keypair("ADMIN1", keypair)
    keys.upsert(pub)
    keys.upsert(priv)

    summaries = collect_admins(nodes, keys, template2, known_bad=frozenset())

    matches = [s for s in summaries if s.ref == "ADMIN1"]
    assert len(matches) == 1
    assert matches[0].in_template is True


def test_collect_admins_keeps_discovering_after_skipping_a_template_admin(
    nodes: NodeRepository, keys: KeyRepository, template, keypair_factory
) -> None:
    """The template-admin dedup skip must continue the loop, never abandon it.

    With a template-configured admin key enumerated BEFORE a fleet-only
    ("extra") one, a `break` regression in the fleet-discovery loop would
    silently truncate `mesh admin list`'s "who has admin access" audit,
    hiding every extra admin discovered after the first template hit. The
    single-key dedup test above cannot tell `continue` and `break` apart.
    """
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1",)})
    nodes.upsert(NodeRecord(node_id="deadbe01", authorized_admin_keys=("ADMIN1_pub", "EXTRA1_pub")))
    admin_pub, _ = KeyRecord.for_keypair("ADMIN1", keypair_factory())
    extra_pub, _ = KeyRecord.for_keypair("EXTRA1", keypair_factory())
    keys.upsert(admin_pub)
    keys.upsert(extra_pub)
    enumerated = [record.key_ref for record in keys.of_type(KeyType.ADMIN_PUBLIC)]
    assert enumerated.index("ADMIN1_pub") < enumerated.index("EXTRA1_pub")

    summaries = collect_admins(nodes, keys, template2, known_bad=frozenset())

    by_ref = {s.ref: s for s in summaries}
    assert by_ref["ADMIN1"].in_template is True
    assert by_ref["EXTRA1"].in_template is False
    assert by_ref["EXTRA1"].authorized_on == ("deadbe01",)


def test_collect_admins_resolves_node_id_from_ref_alone_with_no_key_present(
    nodes: NodeRepository, keys: KeyRepository, template
) -> None:
    """Resolve node_id from a ref that parses as an existing NodeId alone.

    When an admin ref itself parses as a NodeId that exists in the DB,
    node_id must resolve via the direct-parse branch alone -- true even
    with NO Keys-sheet row for this admin at all (present=False), which
    is only possible because this branch doesn't depend on `record` the
    way the key-material-matching fallback does. Isolates the direct-
    parse branch from the fallback: if this test used a ref with a real
    key present, the fallback would independently produce the same
    answer (same key_ref by construction) and the direct branch could be
    deleted without failing it.
    """
    template2 = template.model_copy(update={"admin_nodes": ("deadbe01",)})
    nodes.upsert(NodeRecord(node_id="deadbe01"))
    # Deliberately no Keys-sheet row registered for "deadbe01_pub".

    summaries = collect_admins(nodes, keys, template2, known_bad=frozenset())

    entry = next(s for s in summaries if s.ref == "deadbe01")
    assert entry.present is False
    assert entry.node_id == "deadbe01"


def test_collect_admins_resolves_node_id_via_key_material_match(
    nodes: NodeRepository, keys: KeyRepository, template, keypair: KeyPair
) -> None:
    """Resolve node_id to the right node via key-material matching.

    When an admin ref is a human label (not a node id), but its key
    material matches a node's OWN public key (the node authorized itself
    as its own admin -- or, more commonly, this admin ref's key was
    later adopted as some node's own keypair), node_id must resolve via
    the material-matching fallback to the RIGHT node, not just any node.
    """
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1",)})
    owner_node = NodeRecord(node_id="deadbe01")
    other_node = NodeRecord(node_id="deadbe02")
    nodes.upsert(owner_node)
    nodes.upsert(other_node)
    admin_pub, admin_priv = KeyRecord.for_keypair("ADMIN1", keypair)
    keys.upsert(admin_pub)
    keys.upsert(admin_priv)
    # deadbe01's own public key is the SAME material as ADMIN1's -- the
    # scenario where an admin's key was adopted as a node's own keypair.
    owner_pub, _ = KeyRecord.for_keypair("deadbe01", keypair)
    keys.upsert(owner_pub)

    summaries = collect_admins(nodes, keys, template2, known_bad=frozenset())

    entry = next(s for s in summaries if s.ref == "ADMIN1")
    assert entry.node_id == "deadbe01"
