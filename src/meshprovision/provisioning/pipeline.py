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

import dataclasses
import hmac
import logging
import re
from typing import TYPE_CHECKING, Final

from meshprovision.crypto import redact, weakkeys
from meshprovision.crypto.keys import public_key_matches
from meshprovision.db import schema
from meshprovision.db.observed_keys import is_observed_ref
from meshprovision.db.schema import KeyOrigin, KeyType
from meshprovision.errors import KeyMaterialError, NamespaceExhaustedError, WeakKeySeverity
from meshprovision.provisioning import detect
from meshprovision.provisioning.plan_admin_keys import ResolvedAdminKey

if TYPE_CHECKING:
    from collections.abc import Mapping

    from meshprovision.config.template import TemplateConfig
    from meshprovision.db.keys import KeyRepository
    from meshprovision.db.nodes import NodeRecord, NodeRepository
    from meshprovision.nodeid import NodeId

__all__ = [
    "adopt_would_rotate_admin_key",
    "alias_would_rotate_admin_key",
    "allocate_names",
    "audit_live_admin_keys",
    "audit_node_key",
    "is_host_generated_key",
    "match_admin_key_refs",
    "node_key_admin_refs",
    "resolve_admin_keys",
    "resolve_removed_admin_refs",
]

_logger = logging.getLogger(__name__)

_NODE_ID_SHAPE_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{8}")
"""Matches an owner portion shaped like a raw node id (e.g. ``"deadbe01"``)."""


def _ref_sort_key(ref: str) -> tuple[bool, bool, str]:
    """Sort key implementing :func:`match_admin_key_refs`'s ``PREFERRED`` order.

    Args:
        ref: A ``Keys`` sheet public-key reference (always ``<owner>_pub``
            for the entries this module sorts).

    Returns:
        ``(is_observed, owner_looks_like_a_node_id, ref)``. Sorting
        ascending on this key puts a human-labeled ref (``"ADMIN1_pub"``)
        before a node-id-shaped one (``"deadbe01_pub"``), and both before a
        synthetic ``mesh adopt``-minted ref
        (``"observed-ab12cd34_pub"``, see
        :mod:`meshprovision.db.observed_keys`) -- so once an
        observed key is later registered under a real ref (``mesh admin
        import``) or turns out to be one of the fleet's own node keys, the
        real ref wins automatically over the synthetic one every caller
        of :func:`match_admin_key_refs` still sees. Ties within each group
        are broken lexicographically.
    """
    owner = ref[:-4] if ref.endswith("_pub") else ref
    looks_like_node_id = bool(_NODE_ID_SHAPE_RE.fullmatch(owner))
    return (is_observed_ref(ref), looks_like_node_id, ref)


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


def node_key_admin_refs(
    node_id: NodeId, *, keys: KeyRepository, nodes: NodeRepository, template: TemplateConfig
) -> tuple[str, ...]:
    """Find the admin refs whose material this node's ``<hex>_pub`` row currently backs.

    Used by :func:`~meshprovision.cli.provision.run_provision` to populate
    :attr:`~meshprovision.provisioning.plan_types.PlanInputs.node_key_admin_refs`,
    which gates :func:`~meshprovision.provisioning.plan._plan_node_keypair`:
    a node whose recorded key is also an authorized admin key may not have
    that key silently replaced (adopted or regenerated), because doing so
    would rotate -- or hand an attacker -- the fleet's admin key. See
    :class:`~meshprovision.errors.AdminKeyRotationRefusedError`.

    Determined from **DB material only**, never the live device's
    self-reported key -- the live value is exactly what an impostor
    controls.

    Args:
        node_id: The node to check.
        keys: The already-open key repository.
        nodes: The already-open node repository.
        template: The validated provisioning template.

    Returns:
        Every ``Keys`` sheet public-key reference whose material equals
        this node's ``<hex>_pub`` row and that actually functions as an
        admin ref -- named in ``template.admin_nodes``, or authorized on
        at least one non-archived node's ``authorized_admin_keys``. This
        excludes another node's own identity key merely for sharing the
        same material (the clone/CVE-2025-52464 duplicate-key case) unless
        that other node's ref is itself functioning as an admin the same
        way. Empty when there is no ``<hex>_pub`` row for this node, or
        when the row exists but backs no admin ref at all.
    """
    own_pub = keys.find(schema.ref_for(node_id.hex, KeyType.ADMIN_PUBLIC))
    if own_pub is None:
        return ()
    material = own_pub.material()

    active_nodes = tuple(node for node in nodes.all() if not node.is_archived)
    template_refs = frozenset(template.admin_nodes)

    refs = [
        record.key_ref
        for record in keys.of_type(KeyType.ADMIN_PUBLIC)
        if record.material() == material
        and (
            record.owner_node_id in template_refs
            or any(record.key_ref in node.authorized_admin_keys for node in active_nodes)
        )
    ]
    return tuple(sorted(refs))


def adopt_would_rotate_admin_key(
    *,
    db_public_key: bytes,
    db_has_private_key: bool,
    live_public_key: bytes | None,
    live_private_key: bytes | None,
) -> bool:
    """Decide whether persisting a device's reported key(s) would rotate an admin-bearing key.

    Used by ``mesh adopt`` alongside :func:`node_key_admin_refs`: once
    ``node_key_admin_refs`` shows a node's recorded ``<hex>_pub`` row backs
    an authorized admin key, this decides whether the *specific* material
    the connected (or ``--from-backup``) device reports would actually
    change what is on file -- exactly mirroring
    :func:`~meshprovision.provisioning.plan._plan_node_keypair`'s
    "device_key_differs_from_db" adopt branch, but pure and reusable here
    since ``mesh adopt`` never goes through :func:`~meshprovision.
    provisioning.plan.build_plan`.

    Pure: takes already-extracted material, never a repository, a device,
    or a :class:`~meshprovision.provisioning.detect.LiveConfig`.

    Args:
        db_public_key: The node's recorded ``<hex>_pub`` material. Always
            present when this is worth calling -- :func:`node_key_admin_refs`
            only returns a non-empty tuple when this row exists.
        db_has_private_key: Whether the node also has a recorded
            ``<hex>_priv`` row. Only its existence matters here, never its
            bytes: a device that overwrites it needs to prove possession
            of ``db_public_key``, not reproduce the old private bytes.
        live_public_key: The device's live-reported public key, or
            ``None`` when it reported none.
        live_private_key: The device's live-reported private key, or
            ``None`` when it reported none (or when this is a public-only
            adopt).

    Returns:
        ``True`` when persisting the device's report would change either
        recorded row:

        - The device reports a public key that differs from
          ``db_public_key`` -- an outright key change (or impostor).
        - The device reports a private key, a ``<hex>_priv`` row already
          exists, and that private key does *not* derive
          ``db_public_key`` -- persisting it would silently corrupt the
          DB's only copy of the admin private key with material that
          doesn't even correspond to the recorded public key. A private
          key that *does* derive ``db_public_key`` proves the device
          holds the genuine keypair, so re-recording it (even if the
          existing ``_priv`` row happens to differ, e.g. a prior bad
          write) is allowed through.

        ``False`` -- nothing on file would change -- when the device
        reports no keys at all, reports back exactly what is recorded, or
        reports a private key that proves possession of ``db_public_key``.
    """
    if live_public_key is not None and live_public_key != db_public_key:
        return True
    if live_private_key is not None and db_has_private_key:
        try:
            proves_possession = public_key_matches(live_private_key, db_public_key)
        except KeyMaterialError:
            proves_possession = False
        if not proves_possession:
            return True
    return False


def alias_would_rotate_admin_key(
    *,
    existing_alias_public_key: bytes,
    plan_regenerates: bool,
    plan_adopts_device_key: bool,
    live_public_key: bytes | None,
    db_public_key: bytes | None,
) -> bool:
    """Decide whether ``admin bootstrap --ref R`` would re-point an existing ``R`` to new material.

    Used by :func:`~meshprovision.cli.provision.run_provision` right after
    :func:`~meshprovision.provisioning.plan.build_plan`, when ``opts.admin_ref``
    names an existing ``<admin_ref>_pub`` row: :func:`node_key_admin_refs` only
    catches a rotation of the *connected node's own* recorded key, keyed on its
    DB row. It says nothing about the alias ref itself -- a factory-fresh node
    (no DB row of its own) bootstrapped under an *existing* ``--ref`` sails
    through that check, and ``_register_admin_alias`` then upserts the new
    device's material under ``R`` unconditionally, silently handing the fleet's
    admin ref to a different keypair. This predicate closes that gap by
    checking the alias ref's own existing material instead.

    Pure: takes already-extracted material and plan flags, never a repository,
    a device, or a :class:`~meshprovision.provisioning.detect.LiveConfig`.

    Args:
        existing_alias_public_key: The material already on file for
            ``<admin_ref>_pub``. Only call this when that row exists --
            a brand-new alias ref never rotates anything.
        plan_regenerates: :attr:`~meshprovision.provisioning.plan_admin_keys.
            KeyPlan.regenerate` from the just-built plan. A regenerate always
            produces material that cannot yet be compared (it doesn't exist
            until applied), so it is treated as an unconditional rotation.
        plan_adopts_device_key: :attr:`~meshprovision.provisioning.
            plan_admin_keys.KeyPlan.adopt_device_key` from the just-built
            plan.
        live_public_key: The connected device's live-reported public key.
            This is the material the alias block would register when
            ``plan_adopts_device_key`` is set.
        db_public_key: The connected node's own recorded ``<hex>_pub``
            material. This is the material the alias block would register
            when neither ``plan_regenerates`` nor ``plan_adopts_device_key``
            is set (the key plan changes nothing, so the alias copies
            whatever is already on file for the node).

    Returns:
        ``True`` when registering the alias would change ``R``'s recorded
        material:

        - The plan regenerates the node's key -- the new material is by
          definition not what ``R`` already holds.
        - The material the alias block would otherwise register (the live
          key under adopt, else the node's own DB key) differs from
          ``existing_alias_public_key``.

        ``False`` when the plan would register exactly the material ``R``
        already holds (an idempotent re-run), or when there is no candidate
        material to compare (nothing would actually be registered).
    """
    if plan_regenerates:
        return True
    candidate = live_public_key if plan_adopts_device_key else db_public_key
    if candidate is None:
        return False
    return candidate != existing_alias_public_key


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
                audit_overridable=audit.overridable,
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


def is_host_generated_key(keys: KeyRepository, live: detect.LiveConfig) -> bool:
    """Check whether the device's live keypair is one meshprovision itself generated.

    The CVE-2025-52464 firmware-window check cannot tell a host-generated
    key from a device-generated one just by looking at the live bytes --
    both look like an ordinary 32-byte key. This is the provenance check
    that lets :func:`audit_node_key` skip re-flagging (and so
    re-regenerating) a key that ``mesh provision`` already minted on the
    host, on every subsequent run against the same CVE-window firmware.

    Trusts the recorded ``origin`` only after independently confirming
    the recorded material still matches what the device reports --
    ``origin`` alone is just a label an operator could hand-edit, or that
    could go stale if the device's key was swapped out from under a
    row that still says ``GENERATED``.

    Args:
        keys: The key repository to look up the node's recorded keypair
            in.
        live: The device's normalized live configuration.

    Returns:
        ``True`` only when all of the following hold: the recorded
        ``<hex>_pub`` row exists with ``origin is KeyOrigin.GENERATED``;
        the device reports a public key equal to that row's material;
        the device also reports a private key; a recorded ``<hex>_priv``
        row exists; and its material equals the device's reported
        private key. ``False`` in every other case, including when the
        recorded row predates the ``origin`` column (``origin is None``)
        -- unknown provenance never counts as host-generated.
    """
    security = live.security
    if not security.has_public_key or not security.has_private_key:
        return False
    live_public = security.public_key
    live_private = security.private_key
    if live_public is None or live_private is None:  # pragma: no cover - has_*_key guarantees this
        return False

    pub_record = keys.find(schema.ref_for(live.node_id.hex, KeyType.ADMIN_PUBLIC))
    if pub_record is None or pub_record.origin is not KeyOrigin.GENERATED:
        return False
    if not hmac.compare_digest(pub_record.material(), live_public):
        return False

    priv_record = keys.find(schema.ref_for(live.node_id.hex, KeyType.ADMIN_PRIVATE))
    if priv_record is None:
        return False
    return hmac.compare_digest(priv_record.material(), redact.reveal(live_private))


def audit_node_key(
    live: detect.LiveConfig, *, known_bad: frozenset[bytes], host_generated: bool = False
) -> tuple[bool, str]:
    """Audit a live device's own keypair for the CVE-2025-52464 weak-key condition.

    Args:
        live: The device's normalized live configuration.
        known_bad: The loaded weak-key blocklist.
        host_generated: Whether this key is known -- via
            :func:`is_host_generated_key` -- to have been generated by
            meshprovision itself, not the device. When ``True``, a
            firmware-window finding is suppressed from the compromised
            decision (logged at WARNING instead): the CVE is a
            device-side RNG failure, and a key this host generated was
            never subject to it, whatever firmware the device now
            reports. Every other finding (blocklist, structural
            weakness, an unparseable-firmware warning) still counts in
            full -- host generation is not a blanket exemption.

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
            key_ref=schema.ref_for(live.node_id.hex, KeyType.ADMIN_PUBLIC),
            firmware_version=live.firmware_version,
            known_bad=known_bad,
        )
    except KeyMaterialError as exc:
        return True, f"malformed key material: {exc.reason}"

    if host_generated:
        suppressed = tuple(
            finding
            for finding in result.findings
            if finding.check is weakkeys.WeakKeyCheck.FIRMWARE_WINDOW
            and finding.severity is WeakKeySeverity.CRITICAL
        )
        for finding in suppressed:
            _logger.warning(
                "node key %s_pub: %s -- but this key was generated by meshprovision, "
                "not the device; not regenerating. Upgrade to >= 2.6.11.",
                live.node_id.hex,
                finding.reason,
            )
        if suppressed:
            # AuditResult is frozen: build a filtered copy locally rather
            # than mutating it, so nothing else that might hold a
            # reference to `result` sees the suppression.
            result = dataclasses.replace(
                result,
                findings=tuple(f for f in result.findings if f not in suppressed),
            )

    if result.findings:
        # Mirrors resolve_admin_keys' logging exactly (same log/level
        # choice, same one-line-per-key shape) -- without this, a
        # warning-severity finding about the node's own keypair (a
        # structurally weak key that fell short of CRITICAL, or a
        # firmware version this build couldn't parse) was silently
        # discarded: only the first CRITICAL finding's reason ever left
        # this function, and cli/provision.py has no other access to the
        # result. See Round 35's weakkey-drift review, Finding 3.
        log = _logger.error if result.compromised else _logger.warning
        log("node key %s_pub: %s", live.node_id.hex, result.summary())
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
        for both when the two patterns' slot counts allow it and the
        rendered long name isn't already taken by another node's recorded
        ``long_name`` -- the short and long namespaces are checked
        independently, so a node whose names fell out of lockstep with
        the current pattern's index scheme (an older template, a
        hand-edited row, an imported legacy record) can leave a lower
        index's long name already in use even though its short name at
        that same index is free.

    Raises:
        NamespaceExhaustedError: If the short-name pattern's namespace
            has no unused names remaining.
    """
    if existing is not None and not rename:
        return None, None

    short_spec = template.short_name_spec()
    index, short = nodes.next_free_name(
        short_spec, is_long=False, warn_at=template.name_capacity_warn_utilization
    )
    long_spec = template.long_name_spec()
    try:
        long = long_spec.render(index)
    except NamespaceExhaustedError:
        long = nodes.next_free_name(long_spec, is_long=True)[1]
    else:
        used_long = {name.casefold() for name in nodes.used_long_names()}
        if long.casefold() in used_long:
            long = nodes.next_free_name(long_spec, is_long=True)[1]
    return short, long
