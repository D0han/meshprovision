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
instead of losing the key or spuriously regenerating it again. A node
that firmware >= 2.8 renumbered after the key write (its id derives from
the key) no longer matches its file's name; :func:`find_pending_holding`
finds the file by the keypair the device holds instead.

Imports only :mod:`meshprovision.db.atomic_writer`,
:mod:`meshprovision.db.backups` and :mod:`meshprovision.db.schema` (never
:mod:`meshprovision.db.known_good`),
keeping this module's place in the ``db/`` dependency graph a leaf
alongside it, not a dependent of it.
"""

from __future__ import annotations

import base64
import glob
import hmac
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from meshprovision.crypto.keys import X25519_KEY_SIZE, KeyPair
from meshprovision.crypto.redact import SecretBytes
from meshprovision.db import schema
from meshprovision.db.atomic_writer import write_bytes_atomic
from meshprovision.db.backups import backup_dir_for, backup_name_targets
from meshprovision.errors import NodeIdError
from meshprovision.nodeid import NODE_ID_HEX_WIDTH, NodeId

__all__ = [
    "MAX_PENDING_SCANNED",
    "PendingKeypair",
    "clear_pending",
    "find_pending_holding",
    "load_pending",
    "move_pending",
    "pending_key_path",
    "write_pending",
]

_logger = logging.getLogger(__name__)

_SIDECAR_FORMAT: Final[int] = 1

MAX_PENDING_SCANNED: Final[int] = 256
"""Most pending-keypair files :func:`find_pending_holding` reads in one search."""


def pending_key_path(db_path: Path, node_id: NodeId) -> Path:
    """Resolve one node's pending-keypair sidecar path.

    Args:
        db_path: The database's own path (the sidecar sits in its
            resolved ``backups/`` directory, per
            :func:`meshprovision.db.backups.backup_dir_for`).
        node_id: The node the pending keypair belongs to.

    Returns:
        The path a new pending keypair is written to, named after the
        database's real file (see
        :func:`meshprovision.db.backups.backup_name_targets`), for example
        ``.../backups/nodes_db.pending-deadbe01.json``. This
        matches neither :func:`meshprovision.db.backups.
        _backup_name_re` nor its prefiltering glob (the stem is followed
        by ``"."``, never the ``"-"`` a timestamped backup name requires
        immediately after the stem), so it is never listed, pruned, or
        mistaken for a rotated backup.
    """
    return _pending_paths(db_path, node_id)[0]


def _pending_paths(db_path: Path, node_id: NodeId) -> tuple[Path, ...]:
    """List the paths one node's pending keypair may sit at, the current name first.

    Args:
        db_path: The database's own path.
        node_id: The node the pending keypair belongs to.

    Returns:
        One path per :func:`meshprovision.db.backups.backup_name_targets`
        name: the real file's, then an older spelling's that a version
        naming these files after the path as given may have written.
    """
    directory = backup_dir_for(db_path)
    return tuple(
        directory / f"{name.stem}.pending-{node_id.hex}.json"
        for name in backup_name_targets(db_path)
    )


@dataclass(frozen=True, slots=True)
class PendingKeypair:
    """A node keypair written ahead of a device write, not yet confirmed persisted.

    Attributes:
        node_id: The node this keypair was generated for.
        public: The raw 32-byte public key.
        private: The raw 32-byte private key, wrapped so it is never
            logged or printed by accident.
        created_ts: When this keypair was written ahead, tz-aware UTC.
        path: The file it was loaded from.
    """

    node_id: NodeId
    public: bytes
    private: SecretBytes
    created_ts: datetime
    path: Path

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
    current, *older = _pending_paths(db_path, node_id)
    write_bytes_atomic(current, payload, backup=False)
    # Superseded: an older-spelling file describes an earlier keypair, and
    # would be read again once this one is cleared.
    for path in older:
        _remove_pending_file(path)


def load_pending(db_path: Path, node_id: NodeId) -> PendingKeypair | None:
    """Load a node's pending keypair, if one is on disk and well-formed.

    Never raises: a missing file is the ordinary "nothing pending" case
    and is silent. Anything else wrong (an unreadable file -- permission
    denied, an I/O error, a directory at that path -- or a readable but
    malformed one: bad JSON, an unrecognized format, a wrong-length key,
    a timestamp that does not parse or is out of range in UTC)
    is logged at ``WARNING`` and treated the same as "nothing pending"
    rather than propagated -- a damaged or inaccessible sidecar must
    never block an ordinary provisioning run. A ``created_ts`` without a
    UTC offset (only possible in a hand-edited file) is read as UTC, the
    database's own rule, not as host-local time.

    Looks under the name :func:`pending_key_path` returns first, then
    under an older spelling of the database's name (see
    :func:`meshprovision.db.backups.backup_name_targets`); the first file
    that exists decides.

    Args:
        db_path: The database's own path.
        node_id: The node to look up a pending keypair for.

    Returns:
        The parsed :class:`PendingKeypair`, or ``None``.
    """
    for path in _pending_paths(db_path, node_id):
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            continue
        except OSError as exc:
            _logger.warning("Could not read pending keypair at %s: %s", path, exc)
            return None
        return _parse_pending(path, raw, node_id)
    return None


def _parse_pending(path: Path, raw: bytes, node_id: NodeId) -> PendingKeypair | None:
    """Parse one pending-keypair file's bytes, logging why it is unusable.

    Args:
        path: The file ``raw`` was read from, for messages.
        raw: The file's bytes.
        node_id: The node the file is expected to belong to.

    Returns:
        The parsed :class:`PendingKeypair`, or ``None`` (after a
        ``WARNING``) when the content is malformed or names another node.
    """
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
        created_raw = data["created_ts"]
        if not isinstance(created_raw, str):
            raise TypeError(f"created_ts must be a string, not {type(created_raw).__name__}")
        created_ts = schema.parse_timestamp(created_raw)
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
        created_ts=created_ts,
        path=path,
    )


def move_pending(db_path: Path, old: NodeId, new: NodeId) -> Path | None:
    """Re-file ``old``'s pending keypair under ``new`` (a node renumbered by firmware 2.8).

    The new file is written first, then ``old``'s is cleared, so a failure
    leaves the keypair where it was. Its ``created_ts`` is kept.

    Args:
        db_path: The database's own path.
        old: The id the node had.
        new: The id it has now.

    Returns:
        The new file's path, or ``None`` when ``old`` had no (usable)
        pending keypair.

    Raises:
        AtomicWriteError: If the new file could not be written; ``old``'s
            file is then left in place.
    """
    pending = load_pending(db_path, old)
    if pending is None:
        return None
    keypair = KeyPair(private=pending.private, public=pending.public)
    write_pending(db_path, new, keypair, now=pending.created_ts)
    clear_pending(db_path, old)
    return pending_key_path(db_path, new)


def _pending_files(db_path: Path) -> list[tuple[Path, NodeId]]:
    """List every pending-keypair file of this database with the node id its name carries.

    Args:
        db_path: The database's own path.

    Returns:
        ``(path, node id)`` pairs, the current spelling's first, each
        spelling's by name; a name whose id part is not an 8-digit hex id
        is skipped. Empty when the backup directory cannot be listed.
    """
    found: list[tuple[Path, NodeId]] = []
    directory = backup_dir_for(db_path)
    for name in backup_name_targets(db_path):
        prefix = f"{name.stem}.pending-"
        try:
            paths = sorted(directory.glob(f"{glob.escape(prefix)}*.json"))
        except OSError as exc:
            _logger.warning("Could not list pending keypairs in %s: %s", directory, exc)
            return found
        for path in paths:
            token = path.name[len(prefix) : -len(".json")]
            try:
                node_id = NodeId.from_hex(token)
            except NodeIdError:
                continue
            if len(token) == NODE_ID_HEX_WIDTH and token == node_id.hex:
                found.append((path, node_id))
    return found


def find_pending_holding(
    db_path: Path, *, public: bytes, private: bytes | SecretBytes
) -> PendingKeypair | None:
    """Find the pending keypair, filed under any node id, that a device holds exactly.

    For a node renumbered after the key write (firmware >= 2.8 derives the
    id from the key): its file is still named after the id it had. Both
    halves must match (see :meth:`PendingKeypair.matches`). Never raises;
    an unreadable or malformed file is skipped as :func:`load_pending`
    would treat it.

    Args:
        db_path: The database's own path.
        public: The device's live-reported public key.
        private: The device's live-reported private key.

    Returns:
        The first matching keypair (its :attr:`~PendingKeypair.node_id` is
        the id its file is named after), or ``None``. At most
        :data:`MAX_PENDING_SCANNED` files are read.
    """
    for path, node_id in _pending_files(db_path)[:MAX_PENDING_SCANNED]:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            _logger.warning("Could not read pending keypair at %s: %s", path, exc)
            continue
        pending = _parse_pending(path, raw, node_id)
        if pending is not None and pending.matches(public=public, private=private):
            return pending
    return None


def clear_pending(db_path: Path, node_id: NodeId) -> None:
    """Best-effort removal of a node's pending-keypair sidecar, if any.

    Never raises: called once the database and the device are known to
    agree (or once a pending keypair is known to have never reached the
    device), so a failure to remove the now-stale file must not fail the
    run it is cleaning up after. Removes the file under an older spelling
    of the database's name too (see :func:`load_pending`), so neither can
    be recovered from later.

    Args:
        db_path: The database's own path.
        node_id: The node whose pending keypair to clear.
    """
    for path in _pending_paths(db_path, node_id):
        _remove_pending_file(path)


def _remove_pending_file(path: Path) -> None:
    """Remove one pending-keypair file if it exists, logging (never raising) a failure.

    Args:
        path: The file to remove.
    """
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        _logger.warning("Failed to clear pending keypair at %s: %s", path, exc)
