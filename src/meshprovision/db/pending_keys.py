"""Write-ahead pending keypair: recovers a freshly generated key across an interrupted run.

Between the moment ``mesh provision`` generates a fresh node keypair and
the moment :func:`meshprovision.provisioning.persist.persist_result`
records it, the key exists only in host process memory -- persistence
happens only *after* the device write, the settle delay, the reconnect,
and the read-back verification all succeed. If the outcome is
UNCERTAIN, the operator interrupts the wait, or the process is killed,
the key was already sent to the device (which is now stuck with it) but
is never recorded anywhere retrievable.

This module closes that gap with a small per-node sidecar file, written
*before* the device write (see ``cli/provision.py``'s ``run_provision``)
and cleared once the database and the device are known to agree. A
later ``mesh provision`` of the same node loads it and, if the device's
live-reported keypair still matches it exactly, recovers it automatically
instead of losing the key or spuriously regenerating it again.

Imports only :mod:`meshprovision.db.atomic_writer` and
:mod:`meshprovision.db.backups` (never :mod:`meshprovision.db.known_good`),
keeping this module's place in the ``db/`` dependency graph a leaf
alongside it, not a dependent of it.
"""

from __future__ import annotations

import base64
import hmac
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from meshprovision.crypto.keys import X25519_KEY_SIZE, KeyPair
from meshprovision.crypto.redact import SecretBytes
from meshprovision.db.atomic_writer import write_bytes_atomic
from meshprovision.db.backups import backup_dir_for
from meshprovision.nodeid import NodeId

__all__ = [
    "PendingKeypair",
    "clear_pending",
    "load_pending",
    "pending_key_path",
    "write_pending",
]

_logger = logging.getLogger(__name__)

_SIDECAR_FORMAT: Final[int] = 1


def pending_key_path(db_path: Path, node_id: NodeId) -> Path:
    """Resolve one node's pending-keypair sidecar path.

    Args:
        db_path: The database's own path (the sidecar sits in its
            resolved ``backups/`` directory, per
            :func:`meshprovision.db.backups.backup_dir_for`).
        node_id: The node the pending keypair belongs to.

    Returns:
        For example ``.../backups/nodes_db.pending-deadbe01.json``. This
        matches neither :func:`meshprovision.db.backups.
        _backup_name_re` nor its prefiltering glob (the stem is followed
        by ``"."``, never the ``"-"`` a timestamped backup name requires
        immediately after the stem), so it is never listed, pruned, or
        mistaken for a rotated backup.
    """
    return backup_dir_for(db_path) / f"{db_path.stem}.pending-{node_id.hex}.json"


@dataclass(frozen=True, slots=True)
class PendingKeypair:
    """A node keypair written ahead of a device write, not yet confirmed persisted.

    Attributes:
        node_id: The node this keypair was generated for.
        public: The raw 32-byte public key.
        private: The raw 32-byte private key, wrapped so it is never
            logged or printed by accident.
        created_ts: When this keypair was written ahead, tz-aware UTC.
    """

    node_id: NodeId
    public: bytes
    private: SecretBytes
    created_ts: datetime

    def matches(self, *, public: bytes, private: bytes | SecretBytes) -> bool:
        """Check whether a live-reported keypair is exactly this pending one.

        Both halves must match -- the private half is what proves the
        device being checked is the one this pending keypair was
        actually written to, not merely one that happens to report the
        same public key. Compared in constant time.

        Args:
            public: The live-reported public key.
            private: The live-reported private key.

        Returns:
            ``True`` only when both halves match exactly.
        """
        live_private = private.reveal() if isinstance(private, SecretBytes) else private
        return hmac.compare_digest(self.public, public) and hmac.compare_digest(
            self.private.reveal(), live_private
        )


def write_pending(db_path: Path, node_id: NodeId, keypair: KeyPair, *, now: datetime) -> None:
    """Write a node's freshly generated keypair to its pending sidecar, atomically.

    Called *before* the device write, while the database's write lock is
    already held -- so this is not a new lock-taker.

    Args:
        db_path: The database's own path.
        node_id: The node this keypair is being generated for.
        keypair: The freshly generated keypair.
        now: Timestamp to record.

    Raises:
        AtomicWriteError: If the write fails. Propagates before any
            device write is attempted, so an unwritable backup directory
            fails early rather than after the device already holds a key
            nothing on the host can recall.
    """
    payload = json.dumps(
        {
            "format": _SIDECAR_FORMAT,
            "node_id": node_id.hex,
            "public": base64.b64encode(keypair.public).decode("ascii"),
            "private": base64.b64encode(keypair.private.reveal()).decode("ascii"),
            "created_ts": now.astimezone(UTC).isoformat(),
        }
    ).encode("ascii")
    write_bytes_atomic(pending_key_path(db_path, node_id), payload, backup=False)


def load_pending(db_path: Path, node_id: NodeId) -> PendingKeypair | None:
    """Load a node's pending keypair, if one is on disk and well-formed.

    Never raises: a missing file is the ordinary "nothing pending" case
    and is silent. Anything else wrong (an unreadable file -- permission
    denied, an I/O error, a directory at that path -- or a readable but
    malformed one: bad JSON, an unrecognized format, a wrong-length key)
    is logged at ``WARNING`` and treated the same as "nothing pending"
    rather than propagated -- a damaged or inaccessible sidecar must
    never block an ordinary provisioning run.

    Args:
        db_path: The database's own path.
        node_id: The node to look up a pending keypair for.

    Returns:
        The parsed :class:`PendingKeypair`, or ``None``.
    """
    path = pending_key_path(db_path, node_id)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        _logger.warning("Could not read pending keypair at %s: %s", path, exc)
        return None

    try:
        data = json.loads(raw)
    except ValueError as exc:
        _logger.warning("Malformed pending keypair at %s: %s", path, exc)
        return None

    if not isinstance(data, dict) or data.get("format") != _SIDECAR_FORMAT:
        _logger.warning("Pending keypair at %s has an unrecognized format; ignoring.", path)
        return None

    try:
        recorded_node_id = data["node_id"]
        public = base64.b64decode(data["public"], validate=True)
        private = base64.b64decode(data["private"], validate=True)
        created_ts = datetime.fromisoformat(data["created_ts"])
    except (KeyError, TypeError, ValueError) as exc:
        _logger.warning("Malformed pending keypair at %s: %s", path, exc)
        return None

    if recorded_node_id != node_id.hex:
        _logger.warning(
            "Pending keypair at %s names node %s, not %s; ignoring.",
            path,
            recorded_node_id,
            node_id.hex,
        )
        return None
    if len(public) != X25519_KEY_SIZE or len(private) != X25519_KEY_SIZE:
        _logger.warning("Pending keypair at %s has a wrong-length key; ignoring.", path)
        return None

    return PendingKeypair(
        node_id=node_id,
        public=public,
        private=SecretBytes(private),
        created_ts=created_ts.astimezone(UTC),
    )


def clear_pending(db_path: Path, node_id: NodeId) -> None:
    """Best-effort removal of a node's pending-keypair sidecar, if any.

    Never raises: called once the database and the device are known to
    agree (or once a pending keypair is known to have never reached the
    device), so a failure to remove the now-stale file must not fail the
    run it is cleaning up after.

    Args:
        db_path: The database's own path.
        node_id: The node whose pending keypair to clear.
    """
    path = pending_key_path(db_path, node_id)
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        _logger.warning("Failed to clear pending keypair at %s: %s", path, exc)
