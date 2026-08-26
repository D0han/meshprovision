"""Typed ``Nodes`` sheet model and repository.

:class:`NodeRecord` is the typed, immutable view of one row of the
``Nodes`` sheet, built on top of the untyped ``dict[str, str]`` rows
:mod:`meshprovision.db.ods` reads and writes. :class:`NodeRepository`
wraps a shared :class:`~meshprovision.db.ods.OdsDatabase` session with
typed CRUD operations, plus the pure :func:`find_next_free_name` helper
that walks a provisioning template's suffix alphabet to find the first
unused device name.

**Formula columns are never trusted from a row.** ``main_chipset``,
``private_key_ref``, ``public_key_ref``, and ``channel_psk_ref`` are all
derived from other columns; :mod:`meshprovision.db.ods` has already
recomputed and warned about them by the time a row reaches
:meth:`NodeRecord.from_row`, and :meth:`NodeRecord.to_row` recomputes them
again on the way out, so a :class:`NodeRecord` never carries a stale
derived value forward.

Secret hygiene: :attr:`NodeRecord.ble_pin` is a ``pydantic.SecretStr``.
Nothing in this module ever logs, prints, or f-string-interpolates its
value; the only way to read it back is :meth:`pydantic.SecretStr.
get_secret_value`, called only where a plain cell string must actually be
written (:meth:`NodeRecord.to_row`).
"""

from __future__ import annotations

import logging
from collections.abc import Collection, Mapping
from datetime import UTC, datetime
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from meshprovision import chipsets
from meshprovision.config.template import (
    PatternSpec,
    TemplateWarning,
    check_capacity_utilization,
    ensure_capacity_available,
)
from meshprovision.db import schema
from meshprovision.db.keys import KeyRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.schema import BLE_PIN_LENGTH, FirmwareType, KeyType
from meshprovision.enums import hw_model_table, region_table, role_table
from meshprovision.errors import NamespaceExhaustedError, NodeNotFoundError
from meshprovision.nodeid import NodeId, NodeIdLike

__all__ = [
    "DEFAULT_REGION",
    "DEFAULT_ROLE",
    "NodeRecord",
    "NodeRepository",
    "find_next_free_name",
]

_logger = logging.getLogger(__name__)

DEFAULT_ROLE: Final[str] = "CLIENT"
"""Default value for :attr:`NodeRecord.role`."""

DEFAULT_REGION: Final[str] = "EU_868"
"""Default value for :attr:`NodeRecord.region`.

The :class:`~meshprovision.enums.EnumTable` ``RegionCode`` covering Poland
-- there is no dedicated ``"PL"`` region code in the LoRa RegionCode enum.
"""


def _format_float(value: float | None) -> str:
    """Format an optional float as a trimmed, fixed-precision cell string.

    Args:
        value: The value to format, or ``None``.

    Returns:
        ``""`` when ``value`` is ``None``; otherwise ``value`` fixed to 7
        decimal places with trailing zeros and a trailing decimal point
        stripped.
    """
    if value is None:
        return ""
    return f"{value:.7f}".rstrip("0").rstrip(".")


class NodeRecord(BaseModel):
    """A typed, immutable view of one row of the ``Nodes`` sheet.

    Attributes:
        node_id: Primary key: 8 lowercase hex digits, no leading ``!``.
        short_name: Device short name (<=4 bytes UTF-8), as sent to the
            node.
        long_name: Device long name (<=39 bytes UTF-8), as sent to the
            node.
        hw_model: Hardware model, canonicalized against the installed
            ``HardwareModel`` protobuf enum when non-empty.
        main_chipset: Main MCU/SoC for :attr:`hw_model`. Always a cache:
            :meth:`to_row` recomputes it fresh from :attr:`hw_model` and
            never trusts this field's stored value.
        firmware_type: Firmware flavor running on this node.
        firmware_version: Firmware version string as reported by the
            device.
        gps_lat: Latitude in decimal degrees, ``[-90, 90]``.
        gps_lon: Longitude in decimal degrees, ``[-180, 180]``.
        gps_alt: Altitude in meters.
        first_added_ts: Tz-aware UTC timestamp this node was first added
            to the database.
        last_updated_ts: Tz-aware UTC timestamp this node's record was
            last updated.
        authorized_admin_keys: ``Keys`` sheet references of the admin
            public keys authorized on this node's ``security.adminKey``.
            Zero entries is a valid, deliberate configuration -- never
            drift.
        notes: Free-form operator notes.
        role: Device role, canonicalized against the installed ``Role``
            protobuf enum when non-empty.
        region: LoRa region, canonicalized against the installed
            ``RegionCode`` protobuf enum when non-empty.
        ble_pin: 6-digit BLE pairing PIN (``bluetooth.fixed_pin``), or
            ``None`` if not yet provisioned. Stored as text so leading
            zeros survive; never logged or displayed.
    """

    model_config = ConfigDict(
        frozen=True, extra="forbid", str_strip_whitespace=True, validate_default=True
    )

    node_id: str
    short_name: str = ""
    long_name: str = ""
    hw_model: str = ""
    main_chipset: str = ""
    firmware_type: FirmwareType = FirmwareType.VANILLA
    firmware_version: str = ""
    gps_lat: float | None = Field(default=None, ge=-90.0, le=90.0)
    gps_lon: float | None = Field(default=None, ge=-180.0, le=180.0)
    gps_alt: int | None = None
    first_added_ts: datetime | None = None
    last_updated_ts: datetime | None = None
    authorized_admin_keys: tuple[str, ...] = ()
    notes: str = ""
    role: str = DEFAULT_ROLE
    region: str = DEFAULT_REGION
    ble_pin: SecretStr | None = None

    @field_validator("node_id")
    @classmethod
    def _validate_node_id(cls, value: str) -> str:
        """Normalize ``node_id`` to canonical 8-digit lowercase hex.

        Args:
            value: The raw ``node_id`` value.

        Returns:
            ``NodeId.parse(value).hex``.

        Raises:
            NodeIdError: If ``value`` cannot be parsed as a node id.
        """
        return NodeId.parse(value).hex

    @field_validator("role")
    @classmethod
    def _validate_role(cls, value: str) -> str:
        """Canonicalize ``role`` against the installed ``Role`` enum.

        Args:
            value: The raw ``role`` value.

        Returns:
            ``value`` unchanged when empty; otherwise its canonical name.

        Raises:
            EnumMappingError: If ``value`` is non-empty and unrecognized.
        """
        if not value:
            return value
        return role_table().to_name(value)

    @field_validator("region")
    @classmethod
    def _validate_region(cls, value: str) -> str:
        """Canonicalize ``region`` against the installed ``RegionCode`` enum.

        Args:
            value: The raw ``region`` value.

        Returns:
            ``value`` unchanged when empty; otherwise its canonical name.

        Raises:
            EnumMappingError: If ``value`` is non-empty and unrecognized.
        """
        if not value:
            return value
        return region_table().to_name(value)

    @field_validator("hw_model")
    @classmethod
    def _validate_hw_model(cls, value: str) -> str:
        """Canonicalize ``hw_model`` against the installed ``HardwareModel`` enum.

        Args:
            value: The raw ``hw_model`` value.

        Returns:
            ``value`` unchanged when empty; otherwise its canonical name.

        Raises:
            EnumMappingError: If ``value`` is non-empty and unrecognized.
        """
        if not value:
            return value
        return hw_model_table().to_name(value)

    @field_validator("ble_pin")
    @classmethod
    def _validate_ble_pin(cls, value: SecretStr | None) -> SecretStr | None:
        """Confirm ``ble_pin`` is exactly :data:`BLE_PIN_LENGTH` ASCII digits.

        Args:
            value: The candidate BLE PIN, or ``None``.

        Returns:
            ``value`` unchanged.

        Raises:
            ValueError: If ``value`` is set but is not exactly
                :data:`BLE_PIN_LENGTH` ASCII digits. The message never
                includes the offending value.
        """
        if value is None:
            return value
        raw = value.get_secret_value()
        if not (raw.isascii() and raw.isdigit() and len(raw) == BLE_PIN_LENGTH):
            raise ValueError(f"ble_pin must be exactly {BLE_PIN_LENGTH} ASCII digits")
        return value

    @property
    def node(self) -> NodeId:
        """This record's id as a :class:`~meshprovision.nodeid.NodeId`.

        Returns:
            ``NodeId.from_hex(self.node_id)``.
        """
        return NodeId.from_hex(self.node_id)

    @property
    def private_key_ref(self) -> str:
        """This node's private-key reference in the ``Keys`` sheet.

        Returns:
            ``schema.ref_for(self.node_id, KeyType.ADMIN_PRIVATE)``.
        """
        return schema.ref_for(self.node_id, KeyType.ADMIN_PRIVATE)

    @property
    def public_key_ref(self) -> str:
        """This node's public-key reference in the ``Keys`` sheet.

        Returns:
            ``schema.ref_for(self.node_id, KeyType.ADMIN_PUBLIC)``.
        """
        return schema.ref_for(self.node_id, KeyType.ADMIN_PUBLIC)

    @property
    def channel_psk_ref(self) -> str:
        """This node's channel-PSK reference in the ``Keys`` sheet.

        Returns:
            ``schema.ref_for(self.node_id, KeyType.CHANNEL_PSK)``.
        """
        return schema.ref_for(self.node_id, KeyType.CHANNEL_PSK)

    def to_row(self) -> dict[str, str]:
        """Render this record as a ``Nodes`` sheet row.

        Every derived column (``main_chipset``, ``private_key_ref``,
        ``public_key_ref``, ``channel_psk_ref``) is recomputed fresh here,
        never read from ``self`` -- this is what guarantees a stale value
        set via :meth:`with_updates` can never reach disk.

        Returns:
            The full ``{column_name: text}`` row, covering exactly the 20
            :data:`~meshprovision.db.schema.NODES_SHEET_SPEC` columns.
        """
        return {
            "node_id": self.node_id,
            "short_name": self.short_name,
            "long_name": self.long_name,
            "hw_model": self.hw_model,
            "main_chipset": chipsets.main_chipset(self.hw_model) if self.hw_model else "",
            "firmware_type": self.firmware_type.value,
            "firmware_version": self.firmware_version,
            "gps_lat": _format_float(self.gps_lat),
            "gps_lon": _format_float(self.gps_lon),
            "gps_alt": "" if self.gps_alt is None else str(self.gps_alt),
            "first_added_ts": (
                "" if self.first_added_ts is None else schema.utc_timestamp(self.first_added_ts)
            ),
            "last_updated_ts": (
                "" if self.last_updated_ts is None else schema.utc_timestamp(self.last_updated_ts)
            ),
            "authorized_admin_keys": schema.format_ref_list(self.authorized_admin_keys),
            "notes": self.notes,
            "private_key_ref": self.private_key_ref,
            "public_key_ref": self.public_key_ref,
            "role": self.role,
            "region": self.region,
            "channel_psk_ref": self.channel_psk_ref,
            "ble_pin": "" if self.ble_pin is None else self.ble_pin.get_secret_value(),
        }

    @classmethod
    def from_row(cls, row: Mapping[str, str]) -> NodeRecord:
        """Build a :class:`NodeRecord` from a ``Nodes`` sheet row.

        The row's derived-column values (``main_chipset``,
        ``private_key_ref``, ``public_key_ref``, ``channel_psk_ref``) are
        ignored: :mod:`meshprovision.db.ods` has already recomputed and
        warned about them, and this constructor recomputes
        ``main_chipset`` fresh from ``hw_model`` rather than trusting the
        row.

        Args:
            row: The row's ``{column_name: text}`` values, already
                validated by :mod:`meshprovision.db.ods`.

        Returns:
            The constructed :class:`NodeRecord`.
        """
        hw_model = row.get("hw_model", "")
        gps_lat_raw = row.get("gps_lat", "")
        gps_lon_raw = row.get("gps_lon", "")
        gps_alt_raw = row.get("gps_alt", "")
        first_added_raw = row.get("first_added_ts", "")
        last_updated_raw = row.get("last_updated_ts", "")
        ble_pin_raw = row.get("ble_pin", "")
        return cls(
            node_id=row.get("node_id", ""),
            short_name=row.get("short_name", ""),
            long_name=row.get("long_name", ""),
            hw_model=hw_model,
            main_chipset=chipsets.main_chipset(hw_model) if hw_model else "",
            firmware_type=FirmwareType(row.get("firmware_type") or FirmwareType.VANILLA.value),
            firmware_version=row.get("firmware_version", ""),
            gps_lat=float(gps_lat_raw) if gps_lat_raw else None,
            gps_lon=float(gps_lon_raw) if gps_lon_raw else None,
            gps_alt=int(gps_alt_raw) if gps_alt_raw else None,
            first_added_ts=schema.parse_timestamp(first_added_raw) if first_added_raw else None,
            last_updated_ts=schema.parse_timestamp(last_updated_raw) if last_updated_raw else None,
            authorized_admin_keys=schema.normalize_ref_list(row.get("authorized_admin_keys", "")),
            notes=row.get("notes", ""),
            role=row.get("role") or DEFAULT_ROLE,
            region=row.get("region") or DEFAULT_REGION,
            ble_pin=SecretStr(ble_pin_raw) if ble_pin_raw else None,
        )

    def with_updates(self, **changes: object) -> NodeRecord:
        """Return a new, re-validated :class:`NodeRecord` with fields replaced.

        Matches the project's immutability convention
        (``Settings.with_overrides``): ``self`` is never mutated, and the
        result is fully re-validated rather than shallow-copied, so an
        override that would violate a field constraint is caught
        immediately.

        Args:
            **changes: Field name/value pairs to replace.

        Returns:
            A new, independently validated :class:`NodeRecord`.
        """
        copied = self.model_copy(update=changes, deep=False)
        return NodeRecord.model_validate(copied.model_dump())

    def touched(self, *, now: datetime | None = None) -> NodeRecord:
        """Return a copy with ``last_updated_ts`` set (and ``first_added_ts`` if unset).

        Args:
            now: Timestamp to use. Defaults to the current time.

        Returns:
            A new :class:`NodeRecord` with ``last_updated_ts`` set to
            ``now``, and ``first_added_ts`` also set to ``now`` when it
            was previously unset.
        """
        resolved = now if now is not None else datetime.now(tz=UTC)
        changes: dict[str, object] = {"last_updated_ts": resolved}
        if self.first_added_ts is None:
            changes["first_added_ts"] = resolved
        return self.with_updates(**changes)


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

        Rows are returned in the ``Nodes`` sheet's own order (insertion
        order, never re-sorted), so an operator's hand-ordering of the
        spreadsheet survives a round trip.

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
        """Return every ``short_name`` currently in use.

        Returns:
            The non-empty ``short_name`` values across every node.
        """
        return frozenset(record.short_name for record in self.all() if record.short_name)

    def used_long_names(self) -> frozenset[str]:
        """Return every ``long_name`` currently in use.

        Returns:
            The non-empty ``long_name`` values across every node.
        """
        return frozenset(record.long_name for record in self.all() if record.long_name)

    def next_free_name(
        self, spec: PatternSpec, *, start: int = 0, warn_at: float | None = None
    ) -> tuple[int, str]:
        """Find the next unused name for a compiled pattern, warning near exhaustion.

        Selects the "used" name set (:meth:`used_short_names` or
        :meth:`used_long_names`) by checking whether ``"long"`` appears in
        ``spec.field`` (the template field the pattern was compiled from,
        e.g. ``"long_name_pattern"``), defaulting to short names
        otherwise.

        Args:
            spec: The compiled name pattern to search.
            start: Index to begin searching from.
            warn_at: Utilization ratio at or above which a warning is
                logged. Defaults to
                :data:`~meshprovision.config.template.DEFAULT_WARN_UTILIZATION`
                when ``None``.

        Returns:
            The ``(index, name)`` of the first unused name.

        Raises:
            NamespaceExhaustedError: If ``spec``'s namespace has no
                unused names remaining.
        """
        used = self.used_long_names() if "long" in spec.field else self.used_short_names()
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
