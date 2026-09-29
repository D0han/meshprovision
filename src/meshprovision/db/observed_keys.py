"""Content-addressed refs for admin keys ``mesh adopt`` observes but cannot name.

An admin key a device reports on ``security.adminKey`` may match no
``Keys`` sheet row at all -- a trusted third party's key nobody has
imported yet, or two already-deployed devices sharing a cloned keypair
(CVE-2025-52464). Rather than stash the raw material on the node's
``unregistered_admin_keys`` column (the old behaviour --
:mod:`meshprovision.provisioning.adopt` used to do exactly that), ``mesh
adopt`` now mints a synthetic owner for it and files it in the ``Keys``
sheet like any other key, so it gets a real ``key_ref`` other logic (the
weak-key audit, the cross-fleet duplicate check, ``mesh admin list``) can
reason about uniformly.

The owner is content-addressed -- derived from the key's own material,
never from which node happened to report it first -- so the *same* cloned
key observed on several devices collapses to a single ``Keys`` row every
one of them references, which is exactly what makes a shared admin key
across two node-shaped owners flag as the CVE-2025-52464 signature (see
:mod:`meshprovision.db.verify`) rather than silently duplicating.

This module is pure: it only derives strings from bytes already in hand.
Nothing here touches a repository, upserts a row, or reads the clock --
that belongs to :mod:`meshprovision.provisioning.key_registry`.
"""

from __future__ import annotations

from typing import Final

from meshprovision.crypto import redact
from meshprovision.db import schema
from meshprovision.db.schema import KeyType

__all__ = [
    "OBSERVED_DIGEST_CHARS",
    "OBSERVED_PREFIX",
    "is_observed_owner",
    "is_observed_ref",
    "observed_key_ref",
    "observed_owner",
]

OBSERVED_PREFIX: Final[str] = "observed-"
"""Reserved prefix marking a synthetic, content-addressed admin-key owner.

``mesh admin import``/``mesh admin bootstrap`` refuse to file a
human-chosen ref under this prefix (see
:func:`meshprovision.cli.admin._validate_admin_ref`), so it can never
collide with an operator-assigned reference.
"""

OBSERVED_DIGEST_CHARS: Final[int] = 8
"""Default number of hex fingerprint characters kept in an observed owner.

8 hex characters is 32 bits of the key's own sha256 digest -- ample to
keep two distinct admin keys observed in the same fleet from colliding by
chance; :func:`meshprovision.provisioning.key_registry.register_observed_key`
widens this on the (cryptographically negligible) event of an actual
collision against unrelated material already filed at that ref.
"""


def observed_owner(material: bytes, *, chars: int = OBSERVED_DIGEST_CHARS) -> str:
    """Derive the synthetic ``owner_node_id`` for an unregistered admin key.

    Args:
        material: The raw 32-byte public key material.
        chars: Number of hex fingerprint characters to keep. Widened by
            :func:`~meshprovision.provisioning.key_registry.
            register_observed_key` only on an actual collision.

    Returns:
        ``f"{OBSERVED_PREFIX}{digest}"``, for example
        ``"observed-ab12cd34"``. Deterministic: the same ``material``
        always yields the same owner, which is what lets the same cloned
        key observed on several nodes collapse to one ``Keys`` row.
    """
    digest = redact.fingerprint(material, chars=chars).removeprefix("sha256:")
    return f"{OBSERVED_PREFIX}{digest}"


def observed_key_ref(material: bytes, *, chars: int = OBSERVED_DIGEST_CHARS) -> str:
    """Derive the synthetic ``Keys`` sheet public-key ref for an admin key.

    Args:
        material: The raw 32-byte public key material.
        chars: Number of hex fingerprint characters to keep, forwarded to
            :func:`observed_owner`.

    Returns:
        ``schema.ref_for(observed_owner(material, chars=chars), KeyType.ADMIN_PUBLIC)``,
        for example ``"observed-ab12cd34_pub"``.
    """
    return schema.ref_for(observed_owner(material, chars=chars), KeyType.ADMIN_PUBLIC)


def is_observed_owner(owner: str) -> bool:
    """Whether an ``owner_node_id``/admin reference is a synthetic observed owner.

    Args:
        owner: The candidate owner or admin reference.

    Returns:
        ``True`` if ``owner`` starts with :data:`OBSERVED_PREFIX`.
    """
    return owner.startswith(OBSERVED_PREFIX)


def is_observed_ref(key_ref: str) -> bool:
    """Whether a ``Keys`` sheet ``key_ref`` names a synthetic observed owner.

    Args:
        key_ref: The candidate ``key_ref`` (e.g. ``"observed-ab12cd34_pub"``).

    Returns:
        ``True`` if the owner portion of ``key_ref`` (with any of
        :data:`~meshprovision.db.schema.KEY_REF_SUFFIXES` stripped) starts
        with :data:`OBSERVED_PREFIX`.
    """
    for suffix in schema.KEY_REF_SUFFIXES.values():
        if key_ref.endswith(suffix):
            return is_observed_owner(key_ref[: -len(suffix)])
    return is_observed_owner(key_ref)
