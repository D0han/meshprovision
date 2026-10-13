"""Make every device know its fleet peers and keep them favorited.

A Meshtastic node only keeps the nodes it has heard from in its own NodeDB,
and evicts the least-recently-heard ones when it fills up. For routers and
base stations that must always reach the rest of the fleet (and hold their
public keys for direct messages), that is not good enough: each device
should have every other fleet node as a *contact* (user info and public
key, from the database) and have it *favorited*, which pins the entry.

This module is the whole feature, shared by ``mesh peers`` and the
``sync_peers`` step of ``mesh provision``:

* :func:`build_contacts` / :func:`public_key_map` turn the database's active
  nodes and recorded public keys into :class:`PeerContact` values;
* :func:`read_live_peers` reads what the connected device already has
  (never raises);
* :func:`plan_peers` is pure: it diffs the two into a :class:`PeersPlan`
  that is idempotent, so a second run plans nothing;
* :func:`apply_peers` sends the planned admin messages to the local node.

A device that already holds a *different* public key for a fleet node is
never overwritten: that is either a stale database or a spoofed identity,
and which one is for the operator to decide, so it is reported as a
mismatch and left alone.

Secret hygiene: only *public* keys pass through this module, and none is
ever logged or printed; a fingerprint is the most any message shows.
"""

from __future__ import annotations

import base64
import binascii
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from meshtastic.protobuf import admin_pb2, config_pb2, mesh_pb2

from meshprovision.crypto.keys import X25519_KEY_SIZE
from meshprovision.db import schema
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import connection
from meshprovision.provisioning.device_write import DEVICE_EXCEPTIONS

if TYPE_CHECKING:
    from meshtastic.mesh_interface import MeshInterface
    from meshtastic.node import Node

    from meshprovision.db.keys import KeyRepository
    from meshprovision.db.node_record import NodeRecord

__all__ = [
    "LivePeer",
    "PeerAction",
    "PeerContact",
    "PeersOutcome",
    "PeersPlan",
    "apply_peers",
    "build_contacts",
    "contact_url",
    "plan_peers",
    "public_key_map",
    "read_live_peers",
]

_logger = logging.getLogger(__name__)

CONTACT_URL_PREFIX: Final[str] = "https://meshtastic.org/v/#"
"""Prefix of a shareable-contact URL, as ``Node.addContactURL`` expects it."""


@dataclass(frozen=True, slots=True)
class PeerContact:
    """One fleet node as the database knows it, ready to hand to a device.

    Attributes:
        node_id: The node's id.
        long_name: Its long name, or ``""``.
        short_name: Its short name, or ``""``.
        hw_model: Canonical ``HardwareModel`` name, or ``""``.
        role: Canonical ``Config.DeviceConfig.Role`` name, or ``""``.
        public_key: Its 32-byte public key, or ``None`` when the database
            records none (such a node cannot be added as a contact).
    """

    node_id: NodeId
    long_name: str = ""
    short_name: str = ""
    hw_model: str = ""
    role: str = ""
    public_key: bytes | None = None


@dataclass(frozen=True, slots=True)
class LivePeer:
    """What the connected device's NodeDB holds for one node.

    Attributes:
        public_key: The public key the device holds, or ``None``.
        is_favorite: Whether the device has the node favorited.
    """

    public_key: bytes | None = None
    is_favorite: bool = False


@dataclass(frozen=True, slots=True)
class PeerAction:
    """The writes one fleet node needs on the connected device.

    Attributes:
        contact: The node concerned.
        add_contact: Whether to send it as a contact first.
        favorite: Whether to mark it favorite.
    """

    contact: PeerContact
    add_contact: bool
    favorite: bool


@dataclass(frozen=True, slots=True)
class PeersPlan:
    """The outcome of diffing the fleet against one device's NodeDB.

    Attributes:
        actions: Nodes needing at least one write, in node-id order.
        in_sync: Nodes already known and favorited.
        no_key: Nodes the database has no public key for. They cannot be
            added as contacts; they are still favorited when the device
            already has them.
        key_mismatch: Nodes whose key on the device differs from the
            database's. Nothing is written for them.
    """

    actions: tuple[PeerAction, ...] = ()
    in_sync: tuple[NodeId, ...] = ()
    no_key: tuple[NodeId, ...] = ()
    key_mismatch: tuple[NodeId, ...] = ()

    @property
    def is_empty(self) -> bool:
        """Whether there is nothing to write.

        Returns:
            ``True`` when :attr:`actions` is empty.
        """
        return not self.actions


@dataclass(frozen=True, slots=True)
class PeersOutcome:
    """What :func:`apply_peers` did.

    Attributes:
        added: Nodes sent as contacts.
        favorited: Nodes marked favorite.
        failures: ``(node, message)`` for each write that raised.
    """

    added: tuple[NodeId, ...] = ()
    favorited: tuple[NodeId, ...] = ()
    failures: tuple[tuple[NodeId, str], ...] = ()

    @property
    def ok(self) -> bool:
        """Whether every attempted write was accepted.

        Returns:
            ``True`` when :attr:`failures` is empty.
        """
        return not self.failures


def public_key_map(keys: KeyRepository, nodes: Iterable[NodeRecord]) -> dict[str, bytes]:
    """Collect the recorded public key of each given node.

    Args:
        keys: The ``Keys`` sheet repository.
        nodes: The nodes to look up.

    Returns:
        ``{node_id_hex: 32 key bytes}`` for every node whose
        ``<node>_pub`` row exists and decodes; others are absent.
    """
    by_ref = {record.key_ref: record for record in keys.all()}
    found: dict[str, bytes] = {}
    for node in nodes:
        record = by_ref.get(schema.ref_for(node.node_id, schema.KeyType.ADMIN_PUBLIC))
        if record is not None:
            found[node.node_id] = record.material()
    return found


def build_contacts(
    nodes: Iterable[NodeRecord], public_keys: Mapping[str, bytes]
) -> tuple[PeerContact, ...]:
    """Turn the database's active nodes into contacts.

    Args:
        nodes: Every ``Nodes`` row; archived ones are dropped.
        public_keys: ``{node_id_hex: key bytes}`` from :func:`public_key_map`.

    Returns:
        One contact per active node, ordered by node id.
    """
    contacts = [
        PeerContact(
            node_id=NodeId.parse(node.node_id),
            long_name=node.long_name,
            short_name=node.short_name,
            hw_model=node.hw_model,
            role=node.role,
            public_key=public_keys.get(node.node_id),
        )
        for node in nodes
        if not node.is_archived
    ]
    return tuple(sorted(contacts, key=lambda contact: int(contact.node_id)))


def _decode_public_key(raw: object) -> bytes | None:
    """Decode a ``nodesByNum`` ``user.publicKey`` value, tolerating junk.

    Args:
        raw: The dict value (base64 text, normally).

    Returns:
        The key bytes when ``raw`` is valid base64 of exactly one key's
        size, else ``None``.
    """
    if isinstance(raw, bytes):
        data = raw
    elif isinstance(raw, str) and raw:
        try:
            data = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            return None
    else:
        return None
    return data if len(data) == X25519_KEY_SIZE else None


def read_live_peers(iface: MeshInterface) -> dict[int, LivePeer]:
    """Read the connected device's NodeDB.

    Never raises: an entry that does not look like a node record is
    skipped, so a quirky firmware reply degrades to "unknown" (which
    plans a harmless, idempotent write) instead of aborting the run.

    Args:
        iface: The open interface.

    Returns:
        ``{node_num: LivePeer}`` for every node the device holds.
    """
    nodes: Any = getattr(iface, "nodesByNum", None)
    if not isinstance(nodes, Mapping):
        return {}
    live: dict[int, LivePeer] = {}
    for num, entry in nodes.items():
        if isinstance(num, bool) or not isinstance(num, int) or not isinstance(entry, Mapping):
            continue
        user = entry.get("user")
        raw_key = user.get("publicKey") if isinstance(user, Mapping) else None
        live[num] = LivePeer(
            public_key=_decode_public_key(raw_key),
            is_favorite=entry.get("isFavorite") is True,
        )
    return live


def plan_peers(
    own_node: NodeId | None,
    contacts: Iterable[PeerContact],
    live: Mapping[int, LivePeer],
) -> PeersPlan:
    """Diff the fleet against one device's NodeDB. Pure.

    Args:
        own_node: The connected device's own id, excluded from the plan
            (a node does not need itself as a peer). ``None`` excludes
            nothing.
        contacts: The fleet, from :func:`build_contacts`.
        live: What the device holds, from :func:`read_live_peers`.

    Returns:
        The plan. Running it and re-planning yields an empty one.
    """
    actions: list[PeerAction] = []
    in_sync: list[NodeId] = []
    no_key: list[NodeId] = []
    mismatch: list[NodeId] = []
    for contact in contacts:
        if own_node is not None and contact.node_id == own_node:
            continue
        held = live.get(int(contact.node_id))
        wanted = contact.public_key
        if wanted is None:
            no_key.append(contact.node_id)
        held_key = held.public_key if held is not None else None
        if wanted is not None and held_key is not None and held_key != wanted:
            mismatch.append(contact.node_id)
            continue
        add = wanted is not None and held_key is None
        # The device can only favorite a node it holds, or one it is about
        # to be given as a contact.
        favorite = (held is not None or add) and not (held is not None and held.is_favorite)
        if add or favorite:
            actions.append(PeerAction(contact, add_contact=add, favorite=favorite))
        elif held is not None:
            in_sync.append(contact.node_id)
    return PeersPlan(
        actions=tuple(actions),
        in_sync=tuple(in_sync),
        no_key=tuple(no_key),
        key_mismatch=tuple(mismatch),
    )


def contact_url(contact: PeerContact) -> str:
    """Build the shareable-contact URL ``Node.addContactURL`` consumes.

    Args:
        contact: A contact with a public key.

    Returns:
        ``https://meshtastic.org/v/#<urlsafe base64, unpadded>`` of a
        ``SharedContact`` carrying the node number, names, hardware
        model, role and public key.

    Raises:
        ValueError: If ``contact`` has no public key.
    """
    if contact.public_key is None:
        raise ValueError(f"{contact.node_id.display} has no public key to share")
    shared = admin_pb2.SharedContact()
    shared.node_num = int(contact.node_id)
    shared.user.id = contact.node_id.display
    shared.user.long_name = contact.long_name
    shared.user.short_name = contact.short_name
    if contact.hw_model:
        shared.user.hw_model = mesh_pb2.HardwareModel.Value(contact.hw_model)
    if contact.role:
        shared.user.role = config_pb2.Config.DeviceConfig.Role.Value(contact.role)
    shared.user.public_key = contact.public_key
    token = base64.urlsafe_b64encode(shared.SerializeToString()).decode("ascii").rstrip("=")
    return f"{CONTACT_URL_PREFIX}{token}"


def apply_peers(local_node: Node, plan: PeersPlan) -> PeersOutcome:
    """Send the planned admin messages to the connected (local) node.

    Each action is attempted independently, so one rejected contact does
    not leave the rest of the fleet unprocessed. A contact is always sent
    before its favorite flag, since the device can only favorite a node it
    holds.

    Args:
        local_node: The connected device's ``localNode``.
        plan: The plan from :func:`plan_peers`.

    Returns:
        What was accepted and what raised. A write the device silently
        drops is caught by the caller's read-back, not here.
    """
    caught = (*DEVICE_EXCEPTIONS, *connection.device_io_errors())
    added: list[NodeId] = []
    favorited: list[NodeId] = []
    failures: list[tuple[NodeId, str]] = []
    for action in plan.actions:
        node_id = action.contact.node_id
        try:
            if action.add_contact:
                local_node.addContactURL(contact_url(action.contact))
                added.append(node_id)
            if action.favorite:
                local_node.setFavorite(int(node_id))
                favorited.append(node_id)
        except caught as exc:
            _logger.warning("Peer write for %s failed: %s", node_id.display, exc)
            failures.append((node_id, str(exc) or type(exc).__name__))
    return PeersOutcome(added=tuple(added), favorited=tuple(favorited), failures=tuple(failures))
