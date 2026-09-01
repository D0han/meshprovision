"""Reusable provisioning-pipeline helpers: resolution, audit, and allocation.

The pure/near-pure half of what ``mesh provision`` does before
:func:`meshprovision.provisioning.plan.build_plan` is called -- resolving and
auditing the admin keys named in ``template.admin_nodes``, auditing the keys a
live device already reports, auditing the device's own keypair, allocating
names, and reconciling recorded admin-key refs against an audit's rejections.

Nothing here touches a :class:`~meshprovision.cli.common.CliContext`, a
``DbSession``, a click prompt, or a console. Every function takes repository,
template, or live-config objects already at home in this package, which is what
lets them live below the CLI layer rather than inside it; the CLI-shaped
orchestration that drives them stays in :mod:`meshprovision.cli.provision`.

Secret hygiene: nothing here ever prints or logs raw key bytes. Identification
goes through :func:`meshprovision.crypto.redact.fingerprint`.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Final

from meshprovision.crypto import redact, weakkeys
from meshprovision.errors import KeyMaterialError, NamespaceExhaustedError
from meshprovision.provisioning import detect
from meshprovision.provisioning.plan_admin_keys import ResolvedAdminKey

if TYPE_CHECKING:
    from collections.abc import Mapping

    from meshprovision.config.template import TemplateConfig
    from meshprovision.db.keys import KeyRepository
    from meshprovision.db.nodes import NodeRecord, NodeRepository

__all__ = [
    "allocate_names",
    "audit_live_admin_keys",
    "audit_node_key",
    "match_admin_key_refs",
    "resolve_admin_keys",
    "resolve_removed_admin_refs",
]

_logger = logging.getLogger(__name__)

_NODE_ID_SHAPE_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{8}")
"""Matches an owner portion shaped like a raw node id (e.g. ``"deadbe01"``)."""


def _ref_sort_key(ref: str) -> tuple[bool, str]:
    """Sort key implementing :func:`match_admin_key_refs`'s ``PREFERRED`` order.

    Args:
        ref: A ``Keys`` sheet public-key reference (always ``<owner>_pub``
            for the entries this module sorts).

    Returns:
        ``(owner_looks_like_a_node_id, ref)``. Sorting ascending on this
        key puts a human-labeled ref (``"ADMIN1_pub"``) before a
        node-id-shaped ref (``"deadbe01_pub"``), and breaks ties within
        each group lexicographically.
    """
    owner = ref[:-4] if ref.endswith("_pub") else ref
    looks_like_node_id = bool(_NODE_ID_SHAPE_RE.fullmatch(owner))
    return (looks_like_node_id, ref)


def match_admin_key_refs(material: bytes, public_keys: Mapping[str, bytes]) -> tuple[str, ...]:
    """Find every ``Keys`` sheet ref registering one raw admin public key.

    Resolved ``ref -> material``, never the inverse: ``mesh admin bootstrap
    --ref LABEL`` deliberately files one key under both ``<node_id>_pub`` and
    ``<LABEL>_pub``, so a ``{material: ref}`` map silently drops the alias.

    Args:
        material: The raw public key to match.
        public_keys: ``{key_ref: raw public key}``, as returned by
            :meth:`~meshprovision.db.keys.KeyRepository.public_key_map`.

    Returns:
        Every matching ref, ordered so a human-labeled ref (``"ADMIN1_pub"``)
        precedes a node-id-shaped one (``"deadbe01_pub"``), ties broken
        lexicographically. Empty when the key is registered nowhere.
    """
    return tuple(
        sorted(
            (ref for ref, candidate in public_keys.items() if candidate == material),
            key=_ref_sort_key,
        )
    )


def resolve_admin_keys(
    keys: KeyRepository, template: TemplateConfig, *, known_bad: frozenset[bytes]
) -> tuple[ResolvedAdminKey, ...]:
    """Resolve and audit every configured admin node's public key.

    Deliberately audits with
    :func:`meshprovision.crypto.weakkeys.audit_public_key` (structural +
    blocklist checks only), never with
    :func:`meshprovision.crypto.weakkeys.audit_node`'s
    ``known_public_keys`` cross-fleet duplicate check: ``mesh admin
    bootstrap --ref LABEL`` intentionally files the same public key under
    both ``<node_id>_pub`` and ``<LABEL>_pub``, so a fleet-wide duplicate
    check here would produce a false CRITICAL and wrongly block the
    ``--allow-lockdown`` gate. Cross-fleet duplicate detection is ``mesh
    db verify``'s job, where the alias case is classified explicitly.

    Args:
        keys: The key repository to resolve references against.
        template: The provisioning template naming ``admin_nodes``.
        known_bad: The loaded weak-key blocklist, threaded through from
            the caller so the blocklist file is read at most once per
            run.

    Returns:
        One :class:`~meshprovision.provisioning.plan_admin_keys.ResolvedAdminKey`
        per entry in ``template.admin_nodes``, in template order. Each
        entry's ``has_private`` reflects cryptographic correspondence, not
        mere row presence: a ``_priv`` row that does not derive its
        ``_pub`` row is reported as unavailable (and flagged via
        ``private_mismatch``), because the lockdown gate's only purpose is
        to establish that someone can still administer the node
        afterwards.

    Raises:
        AdminRefUnresolvedError: If any ``admin_nodes`` reference does
            not resolve to a ``Keys`` sheet row.
    """
    resolved: list[ResolvedAdminKey] = []
    for ref in template.admin_nodes:
        record = keys.resolve_admin_refs((ref,))[0]
        material = record.material()
        audit = weakkeys.audit_public_key(material, key_ref=record.key_ref, known_bad=known_bad)
        if audit.findings:
            log = _logger.error if audit.compromised else _logger.warning
            log("admin key %s: %s", record.key_ref, audit.summary())
        has_private = keys.has_private(ref)
        private_mismatch = keys.private_key_mismatch(ref)
        if private_mismatch:
            _logger.warning(
                "admin key %s: the %s_priv row does not derive %s -- treating the private "
                "counterpart as unavailable",
                record.key_ref,
                ref,
                record.key_ref,
            )
        resolved.append(
            ResolvedAdminKey(
                ref=ref,
                key_ref=record.key_ref,
                public=material,
                has_private=has_private,
                audit_ok=not audit.compromised,
                fingerprint=redact.fingerprint(material),
                audit_summary=audit.summary(),
                private_mismatch=private_mismatch,
            )
        )
    return tuple(resolved)


def audit_live_admin_keys(
    live: detect.LiveConfig, *, known_bad: frozenset[bytes]
) -> frozenset[bytes]:
    """Audit the admin keys a live device currently reports, for removal.

    Args:
        live: The device's normalized live configuration.
        known_bad: The loaded weak-key blocklist.

    Returns:
        The subset of ``live.security.admin_keys`` that are malformed or
        failed the weak-key audit and should be dropped from the plan.
    """
    rejected: set[bytes] = set()
    for key in live.security.admin_keys:
        try:
            result = weakkeys.audit_public_key(key, known_bad=known_bad)
        except KeyMaterialError:
            rejected.add(key)
            continue
        if result.compromised:
            rejected.add(key)
    return frozenset(rejected)


def resolve_removed_admin_refs(
    record: NodeRecord | None,
    public_key_map: Mapping[str, bytes],
    rejected: frozenset[bytes],
) -> tuple[str, ...]:
    """Find which of a node's recorded admin-key refs name a rejected live key.

    Resolves ``ref -> material`` rather than ``material -> ref`` on
    purpose: one public key may legitimately be filed under two refs
    (``mesh admin bootstrap --ref LABEL`` does exactly that), so the
    inverse map is lossy, while ``key_ref`` is the ``Keys`` sheet's
    primary key and resolves unambiguously.

    Args:
        record: The node's existing ``Nodes`` row, or ``None``.
        public_key_map: The ``{key_ref: material}`` map from
            :meth:`~meshprovision.db.keys.KeyRepository.public_key_map`.
        rejected: The live admin keys :func:`audit_live_admin_keys`
            flagged for removal.

    Returns:
        The subset of ``record.authorized_admin_keys`` whose material
        is in ``rejected``, in recorded order. Empty when ``record``
        is ``None``, when nothing was rejected, or when no recorded
        ref resolves to rejected material.
    """
    if record is None or not rejected:
        return ()
    return tuple(ref for ref in record.authorized_admin_keys if public_key_map.get(ref) in rejected)


def audit_node_key(live: detect.LiveConfig, *, known_bad: frozenset[bytes]) -> tuple[bool, str]:
    """Audit a live device's own keypair for the CVE-2025-52464 weak-key condition.

    Args:
        live: The device's normalized live configuration.
        known_bad: The loaded weak-key blocklist.

    Returns:
        A ``(compromised, reason)`` pair. ``(False, "")`` when the device
        reports no public key at all (``plan.py`` already forces
        regeneration for missing material, so no audit is needed here).
        Otherwise ``compromised`` reflects the audit result and
        ``reason`` is the first critical finding's reason, or ``""``.
    """
    security = live.security
    if not security.has_public_key:
        return False, ""
    public = security.public_key
    if public is None:  # pragma: no cover - has_public_key already guarantees this
        return False, ""
    try:
        result = weakkeys.audit_node(
            public=public,
            private=security.private_key,
            node_id=live.node_id.display,
            key_ref=f"{live.node_id.hex}_pub",
            firmware_version=live.firmware_version or None,
            known_bad=known_bad,
        )
    except KeyMaterialError:
        return True, "malformed key material"
    reason = next(
        (finding.reason for finding in result.findings if finding.severity == "critical"), ""
    )
    return result.compromised, reason


def allocate_names(
    nodes: NodeRepository, template: TemplateConfig, *, existing: NodeRecord | None, rename: bool
) -> tuple[str | None, str | None]:
    """Allocate a fresh ``short_name``/``long_name`` pair, when one is needed.

    Args:
        nodes: The node repository to check name collisions against.
        template: The provisioning template supplying the name patterns.
        existing: The node's existing database row, or ``None`` for a new
            node.
        rename: Whether an already-provisioned node may be renamed.

    Returns:
        ``(None, None)`` when ``existing`` is set and ``rename`` is
        ``False`` -- :func:`~meshprovision.provisioning.plan.build_plan`
        then keeps the database's (or, failing that, the device's)
        current names. Otherwise a freshly allocated
        ``(short_name, long_name)`` pair, using the same namespace index
        for both when the two patterns' slot counts allow it.

    Raises:
        NamespaceExhaustedError: If the short-name pattern's namespace
            has no unused names remaining.
    """
    if existing is not None and not rename:
        return None, None

    short_spec = template.short_name_spec()
    index, short = nodes.next_free_name(short_spec, warn_at=template.name_capacity_warn_utilization)
    long_spec = template.long_name_spec()
    try:
        long = long_spec.render(index)
    except NamespaceExhaustedError:
        long = nodes.next_free_name(long_spec)[1]
    return short, long
