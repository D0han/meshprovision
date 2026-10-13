"""Tests for ``meshprovision.provisioning.peers``: contacts, planning, applying."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from meshtastic.protobuf import admin_pb2, config_pb2, mesh_pb2

from meshprovision.crypto.known_bad_keys import SMALL_ORDER_POINTS
from meshprovision.db.node_record import NodeRecord
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import peers

pytestmark = pytest.mark.unit

KEY_A = bytes([1]) * 32
KEY_B = bytes([2]) * 32
KEY_C = bytes([3]) * 32
OTHER = bytes([9]) * 32

A = NodeId.parse("a0000001")
B = NodeId.parse("b0000002")
C = NodeId.parse("c0000003")


def _contact(node: NodeId, key: bytes | None = None) -> peers.PeerContact:
    return peers.PeerContact(node, long_name=f"Node {node.hex}", short_name="N", public_key=key)


def _b64(key: bytes) -> str:
    return base64.b64encode(key).decode("ascii")


def _node_record(node_hex: str, *, archived: bool = False) -> NodeRecord:
    return NodeRecord(
        node_id=node_hex,
        long_name=f"Node {node_hex}",
        short_name="N",
        role="ROUTER",
        hw_model="RAK4631",
        archived_at=datetime(2026, 1, 1, tzinfo=UTC) if archived else None,
    )


# --- build_contacts ----------------------------------------------------------------------------


def test_build_contacts_drops_archived_nodes_and_attaches_keys() -> None:
    records = [
        _node_record("b0000002"),
        _node_record("a0000001"),
        _node_record("c0000003", archived=True),
    ]

    contacts = peers.build_contacts(records, {"a0000001": KEY_A})

    assert [c.node_id for c in contacts] == [A, B]
    assert contacts[0].public_key == KEY_A
    assert contacts[1].public_key is None
    assert contacts[0].role == "ROUTER"
    assert contacts[0].hw_model == "RAK4631"


# --- read_live_peers ---------------------------------------------------------------------------


def test_read_live_peers_parses_keys_and_favorites() -> None:
    iface = SimpleNamespace(
        nodesByNum={
            int(A): {"num": int(A), "user": {"publicKey": _b64(KEY_A)}, "isFavorite": True},
            int(B): {"num": int(B), "user": {"id": "!b0000002"}},
        }
    )

    live = peers.read_live_peers(iface)  # type: ignore[arg-type]

    assert live[int(A)] == peers.LivePeer(public_key=KEY_A, is_favorite=True)
    assert live[int(B)] == peers.LivePeer(public_key=None, is_favorite=False)


@pytest.mark.parametrize(
    "nodes",
    [None, [], "x", {"a": {}}, {True: {}}, {5: "not a mapping"}],
    ids=["none", "list", "str", "str-key", "bool-key", "bad-entry"],
)
def test_read_live_peers_never_raises_on_junk(nodes: object) -> None:
    assert peers.read_live_peers(SimpleNamespace(nodesByNum=nodes)) == {}  # type: ignore[arg-type]


@pytest.mark.parametrize("raw", ["not base64!!", _b64(b"short"), 5, "", None])
def test_read_live_peers_ignores_an_unusable_public_key(raw: object) -> None:
    iface = SimpleNamespace(nodesByNum={7: {"user": {"publicKey": raw}}})

    assert peers.read_live_peers(iface)[7].public_key is None  # type: ignore[arg-type]


# --- plan_peers --------------------------------------------------------------------------------


def test_unknown_peer_is_added_and_favorited() -> None:
    plan = peers.plan_peers(A, [_contact(A, KEY_A), _contact(B, KEY_B)], {})

    assert [(a.contact.node_id, a.add_contact, a.favorite) for a in plan.actions] == [
        (B, True, True)
    ]


def test_own_node_is_never_planned() -> None:
    plan = peers.plan_peers(A, [_contact(A, KEY_A)], {})

    assert plan.is_empty
    assert plan.in_sync == ()


def test_known_but_unfavorited_peer_is_only_favorited() -> None:
    live = {int(B): peers.LivePeer(KEY_B, False)}

    plan = peers.plan_peers(A, [_contact(B, KEY_B)], live)

    assert [(a.add_contact, a.favorite) for a in plan.actions] == [(False, True)]


def test_peer_known_without_a_key_gets_the_contact_added() -> None:
    live = {int(B): peers.LivePeer(None, True)}

    plan = peers.plan_peers(A, [_contact(B, KEY_B)], live)

    assert [(a.add_contact, a.favorite) for a in plan.actions] == [(True, False)]


def test_synced_peer_plans_nothing() -> None:
    live = {int(B): peers.LivePeer(KEY_B, True)}

    plan = peers.plan_peers(A, [_contact(B, KEY_B)], live)

    assert plan.is_empty
    assert plan.in_sync == (B,)


def test_a_different_key_on_the_device_is_reported_and_never_overwritten() -> None:
    live = {int(B): peers.LivePeer(OTHER, False)}

    plan = peers.plan_peers(A, [_contact(B, KEY_B)], live)

    assert plan.is_empty
    assert plan.key_mismatch == (B,)


def test_peer_without_a_database_key_is_favorited_only_when_the_device_holds_it() -> None:
    contacts = [_contact(B), _contact(C)]
    live = {int(B): peers.LivePeer(KEY_B, False)}

    plan = peers.plan_peers(A, contacts, live)

    assert [(a.contact.node_id, a.add_contact, a.favorite) for a in plan.actions] == [
        (B, False, True)
    ]
    assert plan.no_key == (B, C)


def test_replanning_after_applying_the_plan_is_empty() -> None:
    contacts = [_contact(A, KEY_A), _contact(B, KEY_B), _contact(C, KEY_C)]
    first = peers.plan_peers(A, contacts, {})
    live = {
        int(a.contact.node_id): peers.LivePeer(a.contact.public_key, True) for a in first.actions
    }

    second = peers.plan_peers(A, contacts, live)

    assert len(first.actions) == 2
    assert second.is_empty
    assert second.in_sync == (B, C)


# --- screen_contacts ---------------------------------------------------------------------------

D = NodeId.parse("d0000004")
E = NodeId.parse("e0000005")
REAL_A = hashlib.sha256(b"peer a").digest()
SHARED = hashlib.sha256(b"cloned").digest()
REAL_E = hashlib.sha256(b"peer e").digest()
SMALL_ORDER = SMALL_ORDER_POINTS[1]


def _screened(public_keys: dict[str, bytes] | None = None) -> tuple[peers.PeerContact, ...]:
    contacts = [
        _contact(A, REAL_A),
        _contact(B, SHARED),
        _contact(C, SHARED),
        _contact(D, SMALL_ORDER),
        _contact(E, REAL_E),
    ]
    keys = {c.node_id.hex: c.public_key for c in contacts if c.public_key is not None}
    return peers.screen_contacts(
        contacts, {**keys, **(public_keys or {})}, known_bad=frozenset(SMALL_ORDER_POINTS)
    )


def test_screen_contacts_flags_shared_and_weak_keys_only() -> None:
    screened = {c.node_id: c.weak_reason for c in _screened()}

    assert screened[A] == ""
    assert screened[E] == ""
    assert "shared with !c0000003" in screened[B]
    assert "shared with !b0000002" in screened[C]
    assert "known-bad key blocklist" in screened[D]


def test_screen_contacts_counts_a_key_shared_with_an_archived_node() -> None:
    screened = {c.node_id: c.weak_reason for c in _screened({"f0000006": REAL_E})}

    assert "shared with !f0000006" in screened[E]


def test_screen_contacts_treats_malformed_material_as_weak() -> None:
    (contact,) = peers.screen_contacts(
        [_contact(B, b"short")], {}, known_bad=frozenset(SMALL_ORDER_POINTS)
    )

    assert contact.weak_reason == "malformed key material"


def test_a_weak_or_shared_key_is_never_added_or_favorited() -> None:
    live = {int(D): peers.LivePeer(None, False)}

    plan = peers.plan_peers(A, _screened(), live)

    assert plan.weak_key == (B, C, D)
    assert [a.contact.node_id for a in plan.actions] == [E]
    assert plan.in_sync == ()


# --- contact_url -------------------------------------------------------------------------------


def _decode_url(url: str) -> admin_pb2.SharedContact:
    assert url.startswith(peers.CONTACT_URL_PREFIX)
    token = url[len(peers.CONTACT_URL_PREFIX) :]
    padded = token + "=" * (-len(token) % 4)
    shared = admin_pb2.SharedContact()
    shared.ParseFromString(base64.urlsafe_b64decode(padded))
    return shared


def test_contact_url_round_trips_through_shared_contact() -> None:
    contact = peers.PeerContact(
        B, long_name="Base B", short_name="BB", hw_model="RAK4631", role="ROUTER", public_key=KEY_B
    )

    shared = _decode_url(peers.contact_url(contact))

    assert shared.node_num == int(B)
    assert shared.user.id == "!b0000002"
    assert shared.user.long_name == "Base B"
    assert shared.user.short_name == "BB"
    assert shared.user.hw_model == mesh_pb2.HardwareModel.RAK4631
    assert shared.user.role == config_pb2.Config.DeviceConfig.Role.ROUTER
    assert shared.user.public_key == KEY_B


def test_contact_url_without_optional_fields_leaves_them_unset() -> None:
    shared = _decode_url(peers.contact_url(_contact(B, KEY_B)))

    assert shared.user.hw_model == mesh_pb2.HardwareModel.UNSET
    assert shared.user.role == config_pb2.Config.DeviceConfig.Role.CLIENT


def test_contact_url_refuses_a_contact_without_a_key() -> None:
    with pytest.raises(ValueError, match="no public key"):
        peers.contact_url(_contact(B))


# --- apply_peers -------------------------------------------------------------------------------


class _FakeLocalNode:
    def __init__(self, *, fail_on: int | None = None, exit_on: int | None = None) -> None:
        self.calls: list[tuple[str, object]] = []
        self._fail_on = fail_on
        self._exit_on = exit_on

    def addContactURL(self, url: str) -> None:  # noqa: N802 -- real Node method name
        num = _decode_url(url).node_num
        if num == self._exit_on:
            raise SystemExit(1)
        if num == self._fail_on:
            raise OSError("serial write failed")
        self.calls.append(("add", num))

    def setFavorite(self, num: int) -> None:  # noqa: N802 -- real Node method name
        self.calls.append(("fav", num))


def test_apply_sends_the_contact_before_the_favorite_flag() -> None:
    plan = peers.plan_peers(A, [_contact(B, KEY_B), _contact(C, KEY_C)], {})
    node = _FakeLocalNode()

    outcome = peers.apply_peers(node, plan)  # type: ignore[arg-type]

    assert node.calls == [("add", int(B)), ("fav", int(B)), ("add", int(C)), ("fav", int(C))]
    assert outcome.ok
    assert outcome.added == (B, C)
    assert outcome.favorited == (B, C)


def test_apply_skips_the_add_for_a_known_peer() -> None:
    plan = peers.plan_peers(A, [_contact(B, KEY_B)], {int(B): peers.LivePeer(KEY_B, False)})
    node = _FakeLocalNode()

    peers.apply_peers(node, plan)  # type: ignore[arg-type]

    assert node.calls == [("fav", int(B))]


def test_one_failed_peer_does_not_stop_the_rest() -> None:
    plan = peers.plan_peers(A, [_contact(B, KEY_B), _contact(C, KEY_C)], {})
    node = _FakeLocalNode(fail_on=int(B))

    outcome = peers.apply_peers(node, plan)  # type: ignore[arg-type]

    assert not outcome.ok
    assert outcome.failures == ((B, "serial write failed"),)
    assert outcome.added == (C,)
    assert ("fav", int(B)) not in node.calls


def test_a_library_exit_is_caught_instead_of_killing_the_process() -> None:
    plan = peers.plan_peers(A, [_contact(B, KEY_B)], {})
    node = _FakeLocalNode(exit_on=int(B))

    outcome = peers.apply_peers(node, plan)  # type: ignore[arg-type]

    assert [node_id for node_id, _ in outcome.failures] == [B]
