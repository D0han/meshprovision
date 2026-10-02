"""Typed ``Nodes`` sheet row model.

:class:`NodeRecord` is the typed, immutable view of one row of the
``Nodes`` sheet, built on top of the untyped ``dict[str, str]`` rows
:mod:`meshprovision.db.ods` reads and writes. Split out of
:mod:`meshprovision.db.nodes` (which re-exports every name here) so that a
caller needing only the row shape -- notably
:meth:`~meshprovision.provisioning.plan_types.ChangePlan.to_record` --
does not pull in the repository and its ODS/file-system I/O.

**Formula columns are never trusted from a row.** ``main_chipset``,
``private_key_ref``, ``public_key_ref``, and ``channel_psk_ref`` are all
derived from other columns; :mod:`meshprovision.db.ods` has already
recomputed and warned about them by the time a row reaches
:meth:`NodeRecord.from_row`, and :meth:`NodeRecord.to_row` recomputes them
again on the way out, so a :class:`NodeRecord` never carries a stale
derived value forward.

Secret hygiene: :attr:`NodeRecord.ble_pin` and each element of
:attr:`NodeRecord.unregistered_admin_keys` are ``pydantic.SecretStr``.
Nothing in this module ever logs, prints, or f-string-interpolates
their values; the only ways to read them back are :meth:`pydantic.
SecretStr.get_secret_value` (called only where a plain cell string must
actually be written, in :meth:`NodeRecord.to_row`) and
:meth:`NodeRecord.unregistered_admin_key_materials` (the only path to
raw bytes, mirroring :meth:`~meshprovision.db.keys.KeyRecord.material`).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from meshprovision import chipsets
from meshprovision.crypto.keys import decode_key, encode_key
from meshprovision.db import schema
from meshprovision.db.schema import BLE_PIN_LENGTH, FirmwareType, KeyType, ManagementMode
from meshprovision.enums import hw_model_table, region_table, role_table
from meshprovision.nodeid import NodeId

__all__ = [
    "DEFAULT_REGION",
    "DEFAULT_ROLE",
    "NodeRecord",
]

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
        long_name: Device long name (<=25 bytes UTF-8, firmware 2.8's
            limit), as sent to the node.
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
            drift. Refs are dropped when a provisioning run revokes the
            live key they name; the list is never reconstructed from the
            device, so it is last-known state, not a mirror.
        notes: Free-form operator notes.
        role: Device role, canonicalized against the installed ``Role``
            protobuf enum when non-empty. An empty cell round-trips as
            empty (genuinely unknown) for an ``OBSERVED`` row, but
            defaults to :data:`DEFAULT_ROLE` for a ``TEMPLATE`` row --
            see :meth:`from_row`.
        region: LoRa region, canonicalized against the installed
            ``RegionCode`` protobuf enum when non-empty. Same
            ``OBSERVED``-vs-``TEMPLATE`` empty-cell handling as
            :attr:`role`.
        ble_pin: 6-digit BLE pairing PIN (``bluetooth.fixed_pin``), or
            ``None`` if not yet provisioned. Stored as text so leading
            zeros survive; never logged or displayed.
        management: Whether mesh provision enforces the template on this
            node, or only observed it (see mesh adopt). Defaults to
            ``OBSERVED``: a blank cell means a human typed the row in by
            hand, so mesh provision should leave it alone -- see
            :meth:`from_row`.
        unregistered_admin_keys: Raw admin public keys (canonical base64,
            :class:`pydantic.SecretStr`-wrapped) mesh adopt observed
            live on this node's ``security.adminKey`` that are not
            registered in the ``Keys`` sheet. A full replace on every
            adopt, same "observed rows mirror live reality" semantics
            as :attr:`authorized_admin_keys`. The only way to the raw
            bytes is :meth:`unregistered_admin_key_materials`.
        archived_at: Tz-aware UTC timestamp this node was archived
            (soft-deleted) via ``mesh db forget``, or ``None`` if it is
            active. An archived row is never removed -- every other
            field, including :attr:`authorized_admin_keys` and
            :attr:`notes`, is preserved for audit history -- but
            :attr:`is_archived` gates whether commands that act on a
            live device should touch it.
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
    management: ManagementMode = ManagementMode.OBSERVED
    unregistered_admin_keys: tuple[SecretStr, ...] = ()
    archived_at: datetime | None = None

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

    @field_validator("unregistered_admin_keys")
    @classmethod
    def _validate_unregistered_admin_keys(
        cls, value: tuple[SecretStr, ...]
    ) -> tuple[SecretStr, ...]:
        """Decode and re-encode every element to its canonical base64 form.

        Mirrors :meth:`~meshprovision.db.keys.KeyRecord._validate_key_value`'s
        canonicalization, applied element-wise, after pydantic's own
        ``tuple[SecretStr, ...]`` coercion has already run.

        Args:
            value: The candidate tuple.

        Returns:
            Each element, canonicalized and de-duplicated (preserving
            first-seen order), matching what the ``BASE64_KEY_LIST`` cell
            validator stores for this column. De-duplication is by
            canonical form, so the bare and
            :data:`~meshprovision.crypto.keys.B64_KEY_PREFIX`-prefixed
            spellings of one key collapse to a single element.

        Raises:
            KeyMaterialError: If any element is not valid key material.
        """
        seen: set[str] = set()
        canonical: list[SecretStr] = []
        for item in value:
            encoded = encode_key(
                decode_key(item.get_secret_value(), field="unregistered_admin_keys")
            )
            if encoded in seen:
                continue
            seen.add(encoded)
            canonical.append(SecretStr(encoded))
        return tuple(canonical)

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

    @property
    def is_archived(self) -> bool:
        """Whether this node has been archived (soft-deleted) via ``mesh db forget``.

        Returns:
            ``True`` if :attr:`archived_at` is set.
        """
        return self.archived_at is not None

    def unregistered_admin_key_materials(self) -> tuple[bytes, ...]:
        """Decode :attr:`unregistered_admin_keys` to raw bytes.

        The only way out of this record to the raw material -- mirrors
        :meth:`~meshprovision.db.keys.KeyRecord.material`.

        Returns:
            Each entry of :attr:`unregistered_admin_keys`, decoded, in
            stored order.

        Raises:
            KeyMaterialError: If any entry of
                :attr:`unregistered_admin_keys` is not valid key material
                (should not happen for a value that already passed field
                validation, but re-checked defensively).
        """
        return tuple(
            decode_key(item.get_secret_value(), field="unregistered_admin_keys")
            for item in self.unregistered_admin_keys
        )

    def to_row(self) -> dict[str, str]:
        """Render this record as a ``Nodes`` sheet row.

        Every derived column (``main_chipset``, ``private_key_ref``,
        ``public_key_ref``, ``channel_psk_ref``) is recomputed fresh here,
        never read from ``self`` -- this is what guarantees a stale value
        set via :meth:`with_updates` can never reach disk.

        Returns:
            The full ``{column_name: text}`` row, covering exactly the 23
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
            "management": self.management.value,
            "unregistered_admin_keys": schema.format_ref_list(
                [item.get_secret_value() for item in self.unregistered_admin_keys]
            ),
            "archived_at": (
                "" if self.archived_at is None else schema.utc_timestamp(self.archived_at)
            ),
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
        archived_raw = row.get("archived_at", "")
        ble_pin_raw = row.get("ble_pin", "")
        # NodeRecord.to_row() always writes an explicit management value, so
        # a blank cell here can only mean a human typed the row in by hand
        # -- nothing meshprovision itself has ever written omits it. That is
        # exactly what OBSERVED means: a node whose live config mesh
        # provision has not enforced and must not touch until --enroll.
        management = ManagementMode(row.get("management") or ManagementMode.OBSERVED.value)
        # An empty role/region cell is anomalous for a TEMPLATE row (build_plan
        # always resolves a real value from the template) and defaults to the
        # template's own factory defaults as a safety net. For an OBSERVED row
        # (mesh adopt, or a hand-added row with no management cell at all) an
        # empty cell is a deliberate, meaningful "unrecognized live value,
        # never guessed" -- defaulting it here would silently re-fabricate
        # state the row never actually had, every time it is reloaded.
        role_default = DEFAULT_ROLE if management is ManagementMode.TEMPLATE else ""
        region_default = DEFAULT_REGION if management is ManagementMode.TEMPLATE else ""
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
            role=row.get("role") or role_default,
            region=row.get("region") or region_default,
            ble_pin=SecretStr(ble_pin_raw) if ble_pin_raw else None,
            management=management,
            unregistered_admin_keys=tuple(
                SecretStr(item)
                for item in schema.normalize_ref_list(row.get("unregistered_admin_keys", ""))
            ),
            archived_at=schema.parse_timestamp(archived_raw) if archived_raw else None,
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
