"""Register an observed admin key, and reconcile it once its owner is known.

Two repository-aware operations that together let ``mesh adopt`` give
every admin key a device reports a real ``Keys`` sheet row, instead of
stashing raw material on ``Nodes.unregistered_admin_keys`` (see
:mod:`meshprovision.provisioning.observed_keys` for why the minted ref is
content-addressed, and :mod:`meshprovision.provisioning.adopt` for how
this module's two functions are wired into the report -> record
pipeline):

- :func:`register_observed_key` files a not-yet-registered admin key
  under a synthetic ``observed-<fingerprint>`` owner, or reuses whatever
  ref (synthetic or real) already covers that exact material.
- :func:`adopt_canonical_ref` is the reconciliation this enables: once a
  key first filed under a synthetic owner turns out to have a real one
  -- ``mesh adopt`` on the node that actually owns the key, or an
  operator running ``mesh admin import``/``mesh admin bootstrap`` -- it
  rewrites every node's ``authorized_admin_keys`` from the synthetic ref
  to the canonical one, deletes the now-superseded synthetic ``Keys``
  row, and drains any legacy ``unregistered_admin_keys`` entry for the
  same material (the direct successor of ``cli/admin.py``'s old
  module-private ``_drop_now_registered_key``, promoted here so both
  ``cli/adopt.py`` and ``cli/admin.py`` can share it instead of
  duplicating it).

Both functions are in-memory only: the caller owns the transaction and
must call ``db.save()`` to persist.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from meshprovision.db import schema
from meshprovision.db.keys import KeyRecord
from meshprovision.db.schema import KeyType
from meshprovision.errors import DbIntegrityError, KeyMaterialError
from meshprovision.provisioning import observed_keys, pipeline

if TYPE_CHECKING:
    from datetime import datetime

    from meshprovision.db.keys import KeyRepository
    from meshprovision.db.nodes import NodeRepository

__all__ = ["adopt_canonical_ref", "register_observed_key"]

_WIDENED_DIGEST_CHARS = 16
"""Fallback digest width :func:`register_observed_key` retries at on collision."""


def register_observed_key(
    nodes: NodeRepository, keys: KeyRepository, material: bytes, *, created_ts: datetime | None
) -> str:
    """Resolve or mint the ``Keys`` sheet ref an observed admin key belongs at.

    Reuses whatever ref (real or already-synthetic) currently registers
    ``material`` exactly, so a device re-adopted after an earlier ``mesh
    adopt`` already minted a synthetic ref for the same key does not mint
    a second one, and so a key that has since been imported under a real
    ref (``mesh admin import``) or turns out to be one of the fleet's own
    node keys resolves to that real ref instead of a synthetic one --
    :func:`~meshprovision.provisioning.pipeline.match_admin_key_refs`
    always sorts a real ref before a synthetic one (see
    :func:`~meshprovision.provisioning.pipeline._ref_sort_key`), so
    ``refs[0]`` here is already the right preference.

    Args:
        nodes: The open node repository. Unused directly -- accepted so
            this function's signature matches
            :func:`adopt_canonical_ref`'s and every call site opens both
            repositories together, but kept for a future caller that
            needs to cross-check node state before minting.
        keys: The open key repository to resolve against and, on a miss,
            upsert into. In-memory only; the caller must call
            ``keys.db.save()`` to persist.
        material: The raw 32-byte public key material to register.
        created_ts: Timestamp to record on a freshly minted row. Unused
            when an existing ref is reused.

    Returns:
        The ``key_ref`` this material is now registered under.

    Raises:
        DbIntegrityError: If both the default-width and widened
            content-addressed refs are already occupied by *different*
            material -- a sha256-collision-scale coincidence, kept as a
            hard failure rather than silently overwriting an unrelated
            row.
    """
    del nodes
    existing = pipeline.match_admin_key_refs(material, keys.public_key_map())
    if existing:
        return existing[0]

    for chars in (observed_keys.OBSERVED_DIGEST_CHARS, _WIDENED_DIGEST_CHARS):
        owner = observed_keys.observed_owner(material, chars=chars)
        ref = schema.ref_for(owner, KeyType.ADMIN_PUBLIC)
        if keys.find(ref) is None:
            keys.upsert(
                KeyRecord.from_material(
                    owner, KeyType.ADMIN_PUBLIC, material, created_ts=created_ts
                )
            )
            return ref

    raise DbIntegrityError(
        f"Could not mint an observed-key ref for a new admin key: both the "
        f"{observed_keys.OBSERVED_DIGEST_CHARS}- and {_WIDENED_DIGEST_CHARS}-character "
        "content-addressed refs are already occupied by different key material.",
        sheet="Keys",
    )


def adopt_canonical_ref(
    nodes: NodeRepository, keys: KeyRepository, *, material: bytes, canonical_owner: str
) -> bool:
    """Reconcile an admin key's synthetic ref/legacy record onto its real owner.

    Call this once ``material``'s real owner is known -- immediately
    after registering ``<canonical_owner>_pub`` in the ``Keys`` sheet.
    Safe to call unconditionally, including when no synthetic ref or
    legacy record exists for this material yet: it then does nothing and
    returns ``False``.

    Args:
        nodes: The open node repository. Every node's
            ``authorized_admin_keys``/``unregistered_admin_keys`` is
            checked and, when it names the superseded ref or carries this
            material, rewritten. In-memory only.
        keys: The open key repository. Any ``observed-*`` row holding
            exactly ``material`` is deleted. In-memory only.
        material: The raw 32-byte public key material now known to
            belong to ``canonical_owner``.
        canonical_owner: The key's real owner (a ``node_id`` hex value or
            a template ``admin_nodes`` reference).

    Returns:
        ``True`` if any ``Keys`` row was deleted or any node's row was
        rewritten; ``False`` if there was nothing to reconcile.
    """
    canonical_ref = schema.ref_for(canonical_owner, KeyType.ADMIN_PUBLIC)
    observed_refs: list[str] = []
    for record in keys.of_type(KeyType.ADMIN_PUBLIC):
        if not observed_keys.is_observed_ref(record.key_ref):
            continue
        try:
            matches = record.material() == material
        except KeyMaterialError:
            # A hand-edited row with malformed material -- not this
            # function's concern to flag (mesh db verify already does),
            # and certainly not one to crash mesh adopt over.
            continue
        if matches:
            observed_refs.append(record.key_ref)

    changed = False
    for node in nodes.all():
        new_authorized: list[str] = []
        seen: set[str] = set()
        row_changed = False
        for ref in node.authorized_admin_keys:
            resolved = canonical_ref if ref in observed_refs else ref
            if resolved != ref:
                row_changed = True
            if resolved in seen:
                row_changed = True
                continue
            seen.add(resolved)
            new_authorized.append(resolved)

        kept_unregistered = tuple(
            encoded
            for encoded, raw in zip(
                node.unregistered_admin_keys,
                node.unregistered_admin_key_materials(),
                strict=True,
            )
            if raw != material
        )
        unregistered_changed = len(kept_unregistered) != len(node.unregistered_admin_keys)

        if row_changed or unregistered_changed:
            nodes.upsert(
                node.with_updates(
                    authorized_admin_keys=tuple(new_authorized),
                    unregistered_admin_keys=kept_unregistered,
                )
            )
            changed = True

    for observed_ref in observed_refs:
        if keys.delete(observed_ref):
            changed = True

    return changed
