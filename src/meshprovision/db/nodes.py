"""Typed ``Nodes`` sheet repository.

:class:`NodeRepository` wraps a shared
:class:`~meshprovision.db.ods.OdsDatabase` session with typed CRUD
operations over :class:`~meshprovision.db.node_record.NodeRecord` rows,
plus the pure :func:`find_next_free_name` helper that walks a
provisioning template's suffix alphabet to find the first unused device
name. The row model itself (:class:`NodeRecord`, :data:`DEFAULT_ROLE`,
:data:`DEFAULT_REGION`) lives in :mod:`meshprovision.db.node_record`,
including its formula-column and secret-hygiene rules; this module
re-exports all three unchanged, so callers may keep importing them from
here.
"""

from __future__ import annotations

import logging
from collections.abc import Collection, Mapping
from datetime import datetime

from meshprovision.db import schema
from meshprovision.db.keys import KeyRepository
from meshprovision.db.node_record import DEFAULT_REGION, DEFAULT_ROLE, NodeRecord
from meshprovision.db.ods import OdsDatabase
from meshprovision.errors import NamespaceExhaustedError, NodeNotFoundError
from meshprovision.name_pattern import (
    PatternSpec,
    TemplateWarning,
    check_capacity_utilization,
    ensure_capacity_available,
)
from meshprovision.nodeid import NodeId, NodeIdLike

__all__ = [
    "DEFAULT_REGION",
    "DEFAULT_ROLE",
    "NodeRecord",
    "NodeRepository",
    "find_next_free_name",
]

_logger = logging.getLogger(__name__)


def find_next_free_name(
    spec: PatternSpec, used: Collection[str], *, start: int = 0
) -> tuple[int, str]:
    """Find the first unused name in a compiled pattern's namespace.

    Pure: performs no I/O. Comparison against ``used`` is case-insensitive
    (``casefold()``), which prevents two devices whose names differ only
    in case from colliding -- the default base36 suffix alphabet is
    upper-case, so this changes nothing in practice, but it protects a
    custom, mixed-case alphabet too.

    Args:
        spec: The compiled name pattern to search.
        used: Every name currently in use (from any pattern; names that
            do not belong to ``spec`` are ignored for the capacity check
            but still checked for collision).
        start: Index to begin searching from.

    Returns:
        The ``(index, name)`` of the first unused name.

    Raises:
        NamespaceExhaustedError: If ``spec``'s namespace has no unused
            names remaining.
    """
    taken = {name.casefold() for name in used if name}
    in_namespace = sum(1 for name in used if spec.parse_index(name) is not None)
    ensure_capacity_available(spec, in_namespace)

    for index in range(start, spec.capacity):
        name = spec.render(index)
        if name.casefold() not in taken:
            return index, name

    raise NamespaceExhaustedError(
        f"No unused name found in pattern {spec.pattern!r} (capacity {spec.capacity}).",
        pattern=spec.pattern,
        capacity=spec.capacity,
    )


class NodeRepository:
    """Typed CRUD over the ``Nodes`` sheet of a shared :class:`OdsDatabase`.

    A thin, stateless view: every read method recomputes its
    :class:`NodeRecord` list fresh from ``db.rows(NODES_SHEET)`` rather
    than caching, so a mutation made through a sibling
    :class:`~meshprovision.db.keys.KeyRepository` sharing the same
    :class:`OdsDatabase` is always visible immediately. Mutating methods
    (:meth:`upsert`, :meth:`delete`) only update the in-memory session --
    the caller owns the transaction and must call ``db.save()`` to
    persist.
    """

    def __init__(self, db: OdsDatabase) -> None:
        """Initialize the repository over a shared database session.

        Args:
            db: The :class:`OdsDatabase` session to read and write
                through.
        """
        self._db = db

    @property
    def db(self) -> OdsDatabase:
        """The underlying database session.

        Returns:
            The :class:`OdsDatabase` this repository wraps.
        """
        return self._db

    def all(self) -> tuple[NodeRecord, ...]:
        """Return every node currently in the database.

        Rows are returned in the ``Nodes`` sheet's canonical order --
        sorted by ``long_name`` (falling back to ``short_name``), natural
        and case-insensitive, tie-broken by ``node_id`` -- via
        :mod:`meshprovision.db.sorting`. This function does not sort
        itself; :class:`~meshprovision.db.ods.OdsDatabase` already
        guarantees the order on every load and mutation.

        Returns:
            Every row of the ``Nodes`` sheet, parsed fresh.
        """
        return tuple(NodeRecord.from_row(row) for row in self._db.rows(schema.NODES_SHEET))

    def find(self, node_id: NodeIdLike) -> NodeRecord | None:
        """Look up one node by id.

        Args:
            node_id: The node id to look up, in any accepted form.

        Returns:
            The matching :class:`NodeRecord`, or ``None`` if not found.
        """
        hex_id = NodeId.parse(node_id).hex
        for record in self.all():
            if record.node_id == hex_id:
                return record
        return None

    def get(self, node_id: NodeIdLike) -> NodeRecord:
        """Look up one node by id, raising when absent.

        Args:
            node_id: The node id to look up, in any accepted form.

        Returns:
            The matching :class:`NodeRecord`.

        Raises:
            NodeNotFoundError: If no node with this id exists.
        """
        record = self.find(node_id)
        if record is None:
            hex_id = NodeId.parse(node_id).hex
            raise NodeNotFoundError(
                f"Node {hex_id!r} not found in database", node_id=hex_id, source="database"
            )
        return record

    def exists(self, node_id: NodeIdLike) -> bool:
        """Check whether a node with this id exists.

        Args:
            node_id: The node id to look up, in any accepted form.

        Returns:
            ``True`` if a matching node exists.
        """
        return self.find(node_id) is not None

    def upsert(self, record: NodeRecord, *, now: datetime | None = None) -> NodeRecord:
        """Insert or update a node's row, in memory only.

        Sets ``last_updated_ts`` to ``now`` (default: the current time)
        and sets ``first_added_ts`` too when it was previously unset --
        via :meth:`NodeRecord.touched`, which handles both the insert and
        update case uniformly. Does not write to disk; call
        ``self.db.save()`` to persist.

        Args:
            record: The node record to store.
            now: Timestamp to use for the touch. Defaults to the current
                time.

        Returns:
            The stored record (after the touch).
        """
        touched = record.touched(now=now)
        new_row = touched.to_row()
        rows = list(self._db.rows(schema.NODES_SHEET))
        updated_rows: list[Mapping[str, str]] = []
        replaced = False
        for row in rows:
            if row.get("node_id") == touched.node_id:
                updated_rows.append(new_row)
                replaced = True
            else:
                updated_rows.append(row)
        if not replaced:
            updated_rows.append(new_row)
        self._db.replace(schema.NODES_SHEET, updated_rows)
        return touched

    def delete(self, node_id: NodeIdLike) -> bool:
        """Delete a node's row, in memory only.

        Does not write to disk; call ``self.db.save()`` to persist.

        Args:
            node_id: The node id to delete, in any accepted form.

        Returns:
            ``True`` if a row was removed; ``False`` if no matching row
            existed.
        """
        hex_id = NodeId.parse(node_id).hex
        rows = list(self._db.rows(schema.NODES_SHEET))
        filtered = [row for row in rows if row.get("node_id") != hex_id]
        if len(filtered) == len(rows):
            return False
        self._db.replace(schema.NODES_SHEET, filtered)
        return True

    def used_short_names(self) -> frozenset[str]:
        """Return every ``short_name`` currently in use by an active node.

        Excludes archived nodes (``mesh db forget``): their row is kept
        for audit history, never deleted, but a decommissioned node's
        name must be free for a replacement device to take -- there is
        no unarchive command, so treating an archived name as
        permanently reserved would leak a slot out of the pattern's
        namespace (and its finite capacity, see
        :func:`~meshprovision.name_pattern.ensure_capacity_available`)
        for good every time a node is retired.

        Returns:
            The non-empty ``short_name`` values across every
            non-archived node.
        """
        return frozenset(
            record.short_name
            for record in self.all()
            if record.short_name and not record.is_archived
        )

    def used_long_names(self) -> frozenset[str]:
        """Return every ``long_name`` currently in use by an active node.

        See :meth:`used_short_names` -- the same archived-node exclusion
        applies here.

        Returns:
            The non-empty ``long_name`` values across every non-archived
            node.
        """
        return frozenset(
            record.long_name for record in self.all() if record.long_name and not record.is_archived
        )

    def next_free_name(
        self,
        spec: PatternSpec,
        *,
        is_long: bool = False,
        start: int = 0,
        warn_at: float | None = None,
    ) -> tuple[int, str]:
        """Find the next unused name for a compiled pattern, warning near exhaustion.

        Args:
            spec: The compiled name pattern to search.
            is_long: Whether ``spec`` compiled ``long_name_pattern``
                (selects :meth:`used_long_names`) rather than
                ``short_name_pattern`` (:meth:`used_short_names`, the
                default). The caller already knows which one it compiled
                -- :attr:`~meshprovision.name_pattern.PatternSpec.field`
                exists only to make error messages actionable and is
                deliberately not inferred from here.
            start: Index to begin searching from.
            warn_at: Utilization ratio at or above which a warning is
                logged. Defaults to
                :data:`~meshprovision.name_pattern.DEFAULT_WARN_UTILIZATION`
                when ``None``.

        Returns:
            The ``(index, name)`` of the first unused name.

        Raises:
            NamespaceExhaustedError: If ``spec``'s namespace has no
                unused names remaining.
        """
        used = self.used_long_names() if is_long else self.used_short_names()
        in_namespace = sum(1 for name in used if spec.parse_index(name) is not None)

        warning: TemplateWarning | None
        if warn_at is not None:
            warning = check_capacity_utilization(spec, in_namespace, warn_at=warn_at)
        else:
            warning = check_capacity_utilization(spec, in_namespace)
        if warning is not None:
            _logger.warning("%s", warning.message)

        return find_next_free_name(spec, used, start=start)

    def unresolved_admin_refs(self, keys: KeyRepository) -> Mapping[str, tuple[str, ...]]:
        """Cross-check every node's ``authorized_admin_keys`` against the ``Keys`` sheet.

        Args:
            keys: The sibling key repository to resolve references
                against.

        Returns:
            A mapping from ``node_id`` to the tuple of its
            ``authorized_admin_keys`` references that do not resolve to a
            row in the ``Keys`` sheet. Nodes with no unresolved
            references are omitted entirely.
        """
        result: dict[str, tuple[str, ...]] = {}
        for record in self.all():
            missing = tuple(ref for ref in record.authorized_admin_keys if keys.find(ref) is None)
            if missing:
                result[record.node_id] = missing
        return result
