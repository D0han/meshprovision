"""Typed ``Keys`` sheet model and repository.

:class:`KeyRecord` is the typed, immutable view of one row of the
``Keys`` sheet, built on top of the untyped ``dict[str, str]`` rows
:mod:`meshprovision.db.ods` reads and writes. :class:`KeyRepository`
wraps a shared :class:`~meshprovision.db.ods.OdsDatabase` session with
typed CRUD operations, plus the lookups that turn a ``key_ref`` into
actual key material -- raw bytes or a
:class:`~meshprovision.crypto.redact.SecretBytes` -- including
admin-reference resolution and the public-key map the weak-key duplicate
check (:func:`meshprovision.crypto.weakkeys.find_duplicate_public_keys`)
consumes.

Secret hygiene: :attr:`KeyRecord.key_value` is a ``pydantic.SecretStr``,
and :meth:`KeyRecord.material` is the *only* function in this module that
returns raw key bytes. No function here ever passes key material into an
exception message, a log call, or an f-string; where a key must be named
for a human, use :attr:`KeyRecord.fingerprint`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel, ConfigDict, SecretStr, field_validator, model_validator

from meshprovision.config.template import admin_private_key_ref, admin_public_key_ref
from meshprovision.crypto import redact
from meshprovision.crypto.keys import KeyPair, decode_key, encode_key
from meshprovision.crypto.redact import SecretBytes
from meshprovision.db import schema
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.schema import KeyType
from meshprovision.errors import (
    AdminRefUnresolvedError,
    DbIntegrityError,
    KeyMaterialError,
    KeyNotFoundError,
)

__all__ = ["KeyMaterial", "KeyRecord", "KeyRepository"]


class KeyRecord(BaseModel):
    """A typed, immutable view of one row of the ``Keys`` sheet.

    Attributes:
        key_ref: Primary key, derived from ``owner_node_id`` and
            ``key_type`` (see :func:`meshprovision.db.schema.ref_for`). A
            :func:`model_validator <pydantic.model_validator>` asserts
            ``key_ref`` agrees with the derivation -- the code-side mirror
            of the ``Keys.key_ref`` column's ODF formula.
        owner_node_id: The node this key belongs to: either a ``node_id``
            hex value, or a template ``admin_nodes`` reference.
        key_type: The kind of key material this row holds.
        key_value: Canonical base64 of exactly 32 raw key bytes. Never
            logged, printed, or f-string-interpolated -- only
            :meth:`material` unwraps it, and even then returns bytes,
            never a printable string.
        created_ts: Tz-aware UTC timestamp this key was recorded.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    key_ref: str
    owner_node_id: str
    key_type: KeyType
    key_value: SecretStr
    created_ts: datetime | None = None

    @field_validator("key_value", mode="before")
    @classmethod
    def _validate_key_value(cls, value: object) -> str:
        """Decode and re-encode ``key_value`` to its canonical base64 form.

        Args:
            value: The raw candidate value: a base64 string, or a
                :class:`~pydantic.SecretStr` already wrapping one.

        Returns:
            The canonical base64 re-encoding of the decoded 32 key bytes.
            Pydantic wraps the returned string in a ``SecretStr`` since
            that is the field's declared type.

        Raises:
            KeyMaterialError: If ``value`` is not a string (or
                ``SecretStr``), or is not valid, canonical base64 encoding
                exactly 32 bytes.
        """
        text: str
        if isinstance(value, SecretStr):
            text = value.get_secret_value()
        elif isinstance(value, str):
            text = value
        else:
            raise KeyMaterialError("key_value must be a string", reason="invalid type")
        raw = decode_key(text, field="key_value")
        return encode_key(raw)

    @model_validator(mode="after")
    def _check_key_ref(self) -> KeyRecord:
        """Confirm ``key_ref`` agrees with ``owner_node_id`` and ``key_type``.

        Returns:
            ``self``, unchanged.

        Raises:
            DbIntegrityError: If ``key_ref`` does not equal
                ``schema.ref_for(owner_node_id, key_type)``.
        """
        expected = schema.ref_for(self.owner_node_id, self.key_type)
        if self.key_ref != expected:
            raise DbIntegrityError(
                f"Keys.key_ref {self.key_ref!r} does not match the value derived from "
                f"owner_node_id={self.owner_node_id!r} and key_type={self.key_type.value!r} "
                f"(expected {expected!r})",
                sheet="Keys",
                cell=None,
            )
        return self

    @property
    def is_secret(self) -> bool:
        """Whether this row holds material that must be kept confidential.

        Returns:
            ``True`` unless :attr:`key_type` is
            :attr:`~meshprovision.db.schema.KeyType.ADMIN_PUBLIC`.
        """
        return self.key_type is not KeyType.ADMIN_PUBLIC

    @property
    def fingerprint(self) -> str:
        """A redacted, non-reversible label for this key.

        Returns:
            For example ``"sha256:ab12cd34"``.
        """
        return redact.fingerprint(self.material())

    def material(self) -> bytes:
        """Decode this record's raw key bytes. The only way out of this record.

        Returns:
            The decoded 32 raw key bytes.

        Raises:
            KeyMaterialError: If :attr:`key_value` is not valid key
                material (should not happen for a value that already
                passed field validation, but re-checked defensively).
        """
        return decode_key(self.key_value.get_secret_value(), field="key_value")

    def secret(self) -> SecretBytes:
        """Return this record's key material wrapped as :class:`SecretBytes`.

        Returns:
            A :class:`~meshprovision.crypto.redact.SecretBytes` wrapping
            :meth:`material`.
        """
        return SecretBytes(self.material())

    def to_row(self) -> dict[str, str]:
        """Render this record as a ``Keys`` sheet row.

        Returns:
            The full ``{column_name: text}`` row, covering exactly the 5
            :data:`~meshprovision.db.schema.KEYS_SHEET_SPEC` columns.
        """
        return {
            "key_ref": self.key_ref,
            "owner_node_id": self.owner_node_id,
            "key_type": self.key_type.value,
            "key_value": self.key_value.get_secret_value(),
            "created_ts": "" if self.created_ts is None else schema.utc_timestamp(self.created_ts),
        }

    @classmethod
    def from_row(cls, row: Mapping[str, str]) -> KeyRecord:
        """Build a :class:`KeyRecord` from a ``Keys`` sheet row.

        Args:
            row: The row's ``{column_name: text}`` values, already
                validated by :mod:`meshprovision.db.ods`.

        Returns:
            The constructed :class:`KeyRecord`.
        """
        created_raw = row.get("created_ts", "")
        return cls(
            key_ref=row.get("key_ref", ""),
            owner_node_id=row.get("owner_node_id", ""),
            key_type=KeyType(row.get("key_type", "")),
            key_value=SecretStr(row.get("key_value", "")),
            created_ts=schema.parse_timestamp(created_raw) if created_raw else None,
        )

    @classmethod
    def from_material(
        cls,
        owner: str,
        key_type: KeyType,
        raw: bytes | SecretBytes,
        *,
        created_ts: datetime | None = None,
    ) -> KeyRecord:
        """Build a :class:`KeyRecord` from raw key bytes.

        Args:
            owner: The owning ``node_id`` or template ``admin_nodes``
                reference.
            key_type: The kind of key ``raw`` holds.
            raw: The raw 32 key bytes, or a :class:`SecretBytes` wrapping
                them.
            created_ts: Timestamp to record. Defaults to unset.

        Returns:
            The constructed :class:`KeyRecord`, with ``key_ref`` derived
            from ``owner`` and ``key_type``.
        """
        raw_bytes = redact.reveal(raw) if isinstance(raw, SecretBytes) else raw
        return cls(
            key_ref=schema.ref_for(owner, key_type),
            owner_node_id=owner,
            key_type=key_type,
            key_value=SecretStr(encode_key(raw_bytes)),
            created_ts=created_ts,
        )

    @classmethod
    def for_keypair(
        cls, owner: str, pair: KeyPair, *, created_ts: datetime | None = None
    ) -> tuple[KeyRecord, KeyRecord]:
        """Build the public/private :class:`KeyRecord` pair for an X25519 keypair.

        Args:
            owner: The owning ``node_id`` or template ``admin_nodes``
                reference.
            pair: The generated or restored keypair.
            created_ts: Timestamp to record on both rows. Defaults to
                unset.

        Returns:
            ``(public_record, private_record)``.
        """
        public_record = cls.from_material(
            owner, KeyType.ADMIN_PUBLIC, pair.public, created_ts=created_ts
        )
        private_record = cls.from_material(
            owner, KeyType.ADMIN_PRIVATE, pair.private, created_ts=created_ts
        )
        return public_record, private_record

    def __repr__(self) -> str:
        """Return a representation that never exposes key material.

        Returns:
            For example
            ``"KeyRecord(key_ref='deadbe01_pub', fingerprint='sha256:ab12cd34')"``.
        """
        return f"KeyRecord(key_ref={self.key_ref!r}, fingerprint={self.fingerprint!r})"


@dataclass(frozen=True, slots=True)
class KeyMaterial:
    """A resolved public/private key pair for one owner, as raw material.

    Attributes:
        key_ref: The public key's reference in the ``Keys`` sheet.
        key_type: The key type identified by :attr:`key_ref`
            (:attr:`~meshprovision.db.schema.KeyType.ADMIN_PUBLIC`).
        public: The raw public key bytes, when a public-key row was
            found.
        private: The private key material, wrapped as
            :class:`~meshprovision.crypto.redact.SecretBytes`, when a
            private-key row was found.
    """

    key_ref: str
    key_type: KeyType
    public: bytes | None = None
    private: SecretBytes | None = None

    def fingerprint(self) -> str | None:
        """A redacted, non-reversible label for this material.

        Prefers :attr:`public` (never secret) over :attr:`private`.

        Returns:
            The fingerprint, or ``None`` if neither :attr:`public` nor
            :attr:`private` is set.
        """
        if self.public is not None:
            return redact.fingerprint(self.public)
        if self.private is not None:
            return redact.fingerprint(self.private)
        return None


class KeyRepository:
    """Typed CRUD over the ``Keys`` sheet of a shared :class:`OdsDatabase`.

    A thin, stateless view: every read method recomputes its
    :class:`KeyRecord` list fresh from ``db.rows(KEYS_SHEET)`` rather than
    caching. Mutating methods (:meth:`upsert`, :meth:`delete`) only
    update the in-memory session -- the caller owns the transaction and
    must call ``db.save()`` to persist.
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

    def all(self) -> tuple[KeyRecord, ...]:
        """Return every key currently in the database.

        Returns:
            Every row of the ``Keys`` sheet, parsed fresh, in the sheet's
            own order.
        """
        return tuple(KeyRecord.from_row(row) for row in self._db.rows(schema.KEYS_SHEET))

    def find(self, key_ref: str) -> KeyRecord | None:
        """Look up one key by reference.

        Args:
            key_ref: The ``key_ref`` to look up.

        Returns:
            The matching :class:`KeyRecord`, or ``None`` if not found.
        """
        for record in self.all():
            if record.key_ref == key_ref:
                return record
        return None

    def get(self, key_ref: str) -> KeyRecord:
        """Look up one key by reference, raising when absent.

        Args:
            key_ref: The ``key_ref`` to look up.

        Returns:
            The matching :class:`KeyRecord`.

        Raises:
            KeyNotFoundError: If no key with this reference exists.
        """
        record = self.find(key_ref)
        if record is None:
            raise KeyNotFoundError(f"Key reference not found: {key_ref!r}", key_ref=key_ref)
        return record

    def material(self, key_ref: str) -> bytes:
        """Resolve a ``key_ref`` to raw key bytes.

        Args:
            key_ref: The ``key_ref`` to resolve.

        Returns:
            The decoded 32 raw key bytes.

        Raises:
            KeyNotFoundError: If no key with this reference exists.
        """
        return self.get(key_ref).material()

    def public_key(self, key_ref: str) -> bytes:
        """Resolve a ``key_ref`` to raw public-key bytes.

        Args:
            key_ref: The ``key_ref`` to resolve.

        Returns:
            The decoded 32 raw public-key bytes.

        Raises:
            KeyNotFoundError: If no key with this reference exists.
            KeyMaterialError: If the referenced row is not an
                :attr:`~meshprovision.db.schema.KeyType.ADMIN_PUBLIC` row.
        """
        record = self.get(key_ref)
        if record.key_type is not KeyType.ADMIN_PUBLIC:
            raise KeyMaterialError(
                f"{key_ref} is not a public key",
                reason=f"key_type is {record.key_type.value!r}, expected 'admin_public'",
            )
        return record.material()

    def private_key(self, key_ref: str) -> SecretBytes:
        """Resolve a ``key_ref`` to private-key material.

        Args:
            key_ref: The ``key_ref`` to resolve.

        Returns:
            The private key, wrapped as :class:`SecretBytes`.

        Raises:
            KeyNotFoundError: If no key with this reference exists.
            KeyMaterialError: If the referenced row is not an
                :attr:`~meshprovision.db.schema.KeyType.ADMIN_PRIVATE`
                row.
        """
        record = self.get(key_ref)
        if record.key_type is not KeyType.ADMIN_PRIVATE:
            raise KeyMaterialError(
                f"{key_ref} is not a private key",
                reason=f"key_type is {record.key_type.value!r}, expected 'admin_private'",
            )
        return record.secret()

    def for_owner(self, owner: str) -> tuple[KeyRecord, ...]:
        """Return every key row belonging to one owner.

        Args:
            owner: The ``owner_node_id`` to filter by.

        Returns:
            The matching rows, in the sheet's own order.
        """
        return tuple(record for record in self.all() if record.owner_node_id == owner)

    def of_type(self, key_type: KeyType) -> tuple[KeyRecord, ...]:
        """Return every key row of one type.

        Args:
            key_type: The :class:`~meshprovision.db.schema.KeyType` to
                filter by.

        Returns:
            The matching rows, in the sheet's own order.
        """
        return tuple(record for record in self.all() if record.key_type is key_type)

    def has_private(self, admin_ref: str) -> bool:
        """Check whether the private counterpart of an admin ref is on hand.

        Args:
            admin_ref: The admin node reference (as it appears in a
                template's ``admin_nodes``), not a ``key_ref``.

        Returns:
            ``True`` if ``admin_private_key_ref(admin_ref)`` resolves to a
            row in the ``Keys`` sheet.
        """
        return self.find(admin_private_key_ref(admin_ref)) is not None

    def resolve_admin_refs(self, refs: Sequence[str]) -> tuple[KeyRecord, ...]:
        """Resolve a sequence of admin node references to their public-key rows.

        Args:
            refs: Admin node references (as they appear in a template's
                ``admin_nodes``), not ``key_ref`` values. An empty
                sequence is valid and returns ``()``.

        Returns:
            The resolved :class:`KeyRecord` rows, one per entry in
            ``refs``, in order.

        Raises:
            AdminRefUnresolvedError: If any reference does not resolve to
                a row in the ``Keys`` sheet.
        """
        resolved: list[KeyRecord] = []
        for ref in refs:
            pub_ref = admin_public_key_ref(ref)
            record = self.find(pub_ref)
            if record is None:
                raise AdminRefUnresolvedError(
                    f"Admin reference {ref!r} does not resolve to a Keys sheet entry "
                    f"({pub_ref!r} not found)",
                    ref=ref,
                )
            resolved.append(record)
        return tuple(resolved)

    def admin_key_bytes(self, refs: Sequence[str]) -> tuple[bytes, ...]:
        """Resolve admin node references directly to raw public-key bytes.

        Args:
            refs: Admin node references, as accepted by
                :meth:`resolve_admin_refs`.

        Returns:
            The raw public-key bytes, ready for
            ``security.adminKey``, one per entry in ``refs``, in order.

        Raises:
            AdminRefUnresolvedError: If any reference does not resolve to
                a row in the ``Keys`` sheet.
        """
        return tuple(record.material() for record in self.resolve_admin_refs(refs))

    def public_key_map(self) -> dict[str, bytes]:
        """Build the ``{key_ref: raw public key}`` map for the weak-key audit.

        Returns:
            A new mapping consumed by
            :func:`meshprovision.crypto.weakkeys.find_duplicate_public_keys`.
        """
        return {record.key_ref: record.material() for record in self.of_type(KeyType.ADMIN_PUBLIC)}

    def keypair_for(self, owner: str) -> KeyMaterial:
        """Resolve whichever of an owner's public/private key rows exist.

        Args:
            owner: The owning ``node_id`` or template ``admin_nodes``
                reference.

        Returns:
            A :class:`KeyMaterial` with :attr:`KeyMaterial.public` and/or
            :attr:`KeyMaterial.private` set to whichever rows were found
            (either, both, or neither).
        """
        pub_ref = schema.ref_for(owner, KeyType.ADMIN_PUBLIC)
        priv_ref = schema.ref_for(owner, KeyType.ADMIN_PRIVATE)
        pub_record = self.find(pub_ref)
        priv_record = self.find(priv_ref)
        return KeyMaterial(
            key_ref=pub_ref,
            key_type=KeyType.ADMIN_PUBLIC,
            public=pub_record.material() if pub_record is not None else None,
            private=priv_record.secret() if priv_record is not None else None,
        )

    def upsert(self, record: KeyRecord) -> KeyRecord:
        """Insert or update a key's row, in memory only.

        Does not write to disk; call ``self.db.save()`` to persist.

        Args:
            record: The key record to store.

        Returns:
            ``record``, unchanged.
        """
        new_row = record.to_row()
        rows = list(self._db.rows(schema.KEYS_SHEET))
        updated_rows: list[Mapping[str, str]] = []
        replaced = False
        for row in rows:
            if row.get("key_ref") == record.key_ref:
                updated_rows.append(new_row)
                replaced = True
            else:
                updated_rows.append(row)
        if not replaced:
            updated_rows.append(new_row)
        self._db.replace(schema.KEYS_SHEET, updated_rows)
        return record

    def delete(self, key_ref: str) -> bool:
        """Delete a key's row, in memory only.

        Does not write to disk; call ``self.db.save()`` to persist.

        Args:
            key_ref: The ``key_ref`` to delete.

        Returns:
            ``True`` if a row was removed; ``False`` if no matching row
            existed.
        """
        rows = list(self._db.rows(schema.KEYS_SHEET))
        filtered = [row for row in rows if row.get("key_ref") != key_ref]
        if len(filtered) == len(rows):
            return False
        self._db.replace(schema.KEYS_SHEET, filtered)
        return True
