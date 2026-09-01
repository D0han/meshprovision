"""Admin-key material: resolution vocabulary and the desired-set decision.

The cohesive admin-key half of :mod:`meshprovision.provisioning.plan`, extracted
for size. Same purity contract as its parent -- zero I/O, zero device access, zero
clock reads, and it imports nothing from :mod:`meshprovision.crypto` (digests are
the caller's job). :class:`ResolvedAdminKey` reuses its caller-supplied
``fingerprint`` field and :class:`KeyPlan` renders a fixed ``<redacted>``
placeholder for key material in its ``__repr__``, so raw key bytes never reach a
``repr()``.

**The admin-key rule** (:func:`_plan_admin_key_material`), documented
here verbatim per the design brief: ``resolved`` is the caller-supplied,
already-audited public keys named in ``template.admin_nodes``, in
template order. ``live_keys`` is whatever the device currently reports
in ``security.admin_key``. ``kept`` is ``live_keys`` with any
caller-flagged weak key removed. If ``template.admin_nodes`` is *empty*,
that means "no opinion" and the plan's desired set is ``kept`` --
an empty ``admin_nodes`` list never means "strip whatever is on the
device," and a node with zero admin keys is therefore never flagged as
drift. "No opinion" governs what is *written to the device*; it does
not license the database to keep asserting a key the same run just
revoked. When the live weak-key audit drops a key the ``Nodes`` row
named, that ref is removed from
:attr:`~meshprovision.db.nodes.NodeRecord.authorized_admin_keys` -- see
:attr:`KeyPlan.removed_admin_key_refs`. The row is only ever *narrowed*
on this path, never rebuilt: a live admin key with no ``Keys`` sheet row
cannot be named, so the row remains last-known state rather than a
device mirror. If ``template.admin_nodes`` is *non-empty*, it is authoritative:
the desired set is every entry of ``resolved`` that **passed the
weak-key audit** (``audit_ok``), and any live key not named in it is
removed and reported as a ``"live_admin_key_revoked"`` warning (see
:attr:`KeyPlan.revoked_admin_fingerprints`), distinct from a live key
dropped by the weak-key audit itself. Either way the sets are compared
as **sorted** tuples, so a mere ordering difference is never churn.

An entry that failed the weak-key audit is never authorized: it is
excluded from the desired set, named in
:attr:`KeyPlan.rejected_admin_key_refs`, and reported as a
``"resolved_admin_key_rejected"`` warning. This exclusion holds
**regardless of** ``security.is_managed`` -- it is not a lockdown-only
behavior, so an ordinary (unmanaged) provisioning run will not write a
known-compromised key to a device either. The stricter
``is_managed=true`` path additionally refuses the whole run outright
(see :func:`_evaluate_lockdown`).

:attr:`PlanInputs.allow_weak_admin_key` (``--allow-weak-admin-key``)
overrides the exclusion only: the flagged entries are authorized and
reported as ``"resolved_admin_key_forced"`` warnings instead. It does
**not** reach :func:`_evaluate_lockdown`, whose ``is_managed=true``
refusal stands regardless.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from meshprovision.errors import MAX_ADMIN_KEYS, AdminKeyCapacityError
from meshprovision.provisioning.plan_warnings import PlanWarning

if TYPE_CHECKING:
    from meshprovision.provisioning.plan import PlanInputs

__all__ = [
    "KeyPlan",
    "ResolvedAdminKey",
]


@dataclass(frozen=True, slots=True)
class ResolvedAdminKey:
    """One admin node's resolved, audited public key.

    Built by the caller (the CLI layer or ``repair.py``, never this
    module) from the ``Keys`` sheet before :func:`build_plan` is called
    -- see the module docstring.

    Attributes:
        ref: The ``admin_nodes`` entry this key belongs to (e.g.
            ``"ADMIN1"``).
        key_ref: The resolved ``Keys`` sheet reference (e.g.
            ``"ADMIN1_pub"``).
        public: The raw 32-byte X25519 public key.
        has_private: Whether the matching private key is also present in
            the ``Keys`` sheet.
        audit_ok: Whether this key passed the weak-key audit.
        fingerprint: A redacted fingerprint label for :attr:`public`,
            computed by the caller.
        audit_summary: Human-readable summary of the audit result.
        private_mismatch: Whether a private counterpart row exists but does
            not derive this public key. Distinct from ``has_private=False``,
            which also covers simple absence.
    """

    ref: str
    key_ref: str
    public: bytes
    has_private: bool
    audit_ok: bool
    fingerprint: str
    audit_summary: str = ""
    private_mismatch: bool = False

    def __repr__(self) -> str:
        """Return a repr that never exposes :attr:`public`'s raw bytes.

        Returns:
            The default-shaped dataclass repr, with :attr:`public`
            replaced by its already-computed :attr:`fingerprint`.
        """
        return (
            f"ResolvedAdminKey(ref={self.ref!r}, key_ref={self.key_ref!r}, "
            f"public=<redacted:{self.fingerprint}>, has_private={self.has_private!r}, "
            f"audit_ok={self.audit_ok!r}, fingerprint={self.fingerprint!r}, "
            f"audit_summary={self.audit_summary!r})"
        )


@dataclass(frozen=True, slots=True)
class KeyPlan:
    """The plan's decisions about the node's keypair and admin keys.

    Attributes:
        regenerate: Whether a fresh node keypair should be generated and
            written.
        regenerate_reason: Why, when :attr:`regenerate` is set: one of
            ``"forced"``, ``"factory_key_presumed_compromised"``,
            ``"missing_key_material"``, or the caller's own
            ``node_key_reason``/``"weak_key_audit"``.
        adopt_device_key: Whether to record the device's own reported
            public key into the database instead of overwriting it (per
            firmware issue #7449 -- a restored key can silently fail to
            persist across a reboot).
        change_admin_keys: Whether ``security.admin_key`` needs writing.
        desired_admin_keys: The raw public keys the plan wants
            authorized, in write order. Never rendered by
            :meth:`__repr__`.
        desired_admin_key_refs: The ``Keys`` sheet references
            corresponding to :attr:`desired_admin_keys`, in the same
            order -- empty when the desired set came from the device's
            own live keys rather than a resolved ``admin_nodes`` list
            (see the module docstring's admin-key rule).
        removed_admin_fingerprints: Positional labels
            (``"live-admin[0]"``, ...) for live admin keys dropped
            because the caller's weak-key audit flagged them.
        revoked_admin_fingerprints: Positional labels
            (``"live-admin[0]"``, ...) for live admin keys dropped only
            because ``template.admin_nodes`` is non-empty and does not
            name them -- the counterpart of
            :attr:`removed_admin_fingerprints` for keys that passed the
            weak-key audit but were simply not asked for.
        removed_admin_key_refs: The ``Keys`` sheet references on the
            existing ``Nodes`` row whose material the caller's weak-key
            audit flagged for removal -- the database-record counterpart
            of :attr:`removed_admin_fingerprints`, which names the same
            keys positionally for the device write. Resolved by the
            caller, which alone can map a ref to key material. **Not**
            index-aligned with :attr:`removed_admin_fingerprints`: a
            removed live key with no ``Keys`` sheet row contributes
            nothing here.
        rejected_admin_key_refs: The ``Keys`` sheet references named in
            ``template.admin_nodes`` that this plan refuses to authorize
            because the caller's weak-key audit flagged them. The
            counterpart of :attr:`removed_admin_fingerprints` for keys
            resolved from the template rather than read off the device.
    """

    regenerate: bool = False
    regenerate_reason: str = ""
    adopt_device_key: bool = False
    change_admin_keys: bool = False
    desired_admin_keys: tuple[bytes, ...] = ()
    desired_admin_key_refs: tuple[str, ...] = ()
    removed_admin_fingerprints: tuple[str, ...] = ()
    revoked_admin_fingerprints: tuple[str, ...] = ()
    removed_admin_key_refs: tuple[str, ...] = ()
    rejected_admin_key_refs: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        """Whether this plan has nothing to write.

        Returns:
            ``True`` if neither the node keypair nor the admin keys need
            any change.
        """
        return not (self.regenerate or self.adopt_device_key or self.change_admin_keys)

    def __repr__(self) -> str:
        """Return a repr that never exposes raw admin-key bytes.

        Returns:
            The default-shaped dataclass repr, with each entry of
            :attr:`desired_admin_keys` replaced by ``<redacted>``.
        """
        redacted_keys = tuple("<redacted>" for _ in self.desired_admin_keys)
        return (
            f"KeyPlan(regenerate={self.regenerate!r}, "
            f"regenerate_reason={self.regenerate_reason!r}, "
            f"adopt_device_key={self.adopt_device_key!r}, "
            f"change_admin_keys={self.change_admin_keys!r}, "
            f"desired_admin_keys={redacted_keys!r}, "
            f"desired_admin_key_refs={self.desired_admin_key_refs!r}, "
            f"removed_admin_fingerprints={self.removed_admin_fingerprints!r}, "
            f"revoked_admin_fingerprints={self.revoked_admin_fingerprints!r}, "
            f"removed_admin_key_refs={self.removed_admin_key_refs!r}, "
            f"rejected_admin_key_refs={self.rejected_admin_key_refs!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class _AdminKeyPlan:
    """:func:`_plan_admin_key_material`'s result, bundled.

    ``repr`` is suppressed rather than customized: :attr:`desired` holds
    raw key bytes, and this private helper has no fingerprint of its own
    to render in their place.

    Attributes:
        desired: The desired raw admin-key bytes, in write order.
        desired_refs: The ``Keys`` sheet refs corresponding to
            :attr:`desired`, empty when the desired set came from the
            device's own live keys rather than a resolved
            ``admin_nodes`` list.
        change_admin_keys: Whether ``security.admin_key`` needs writing.
        removed: Positional labels for live keys dropped by the audit.
        revoked: Positional labels for live keys dropped only because
            they are absent from a non-empty ``template.admin_nodes``.
        removed_refs: ``Keys`` sheet refs on the existing ``Nodes`` row
            naming a removed live key, passed through from the caller.
        rejected_refs: ``Keys`` sheet refs excluded from :attr:`desired`
            because they failed the audit.
        warnings: The corresponding rejection warnings.
    """

    desired: tuple[bytes, ...]
    desired_refs: tuple[str, ...]
    change_admin_keys: bool
    removed: tuple[str, ...]
    revoked: tuple[str, ...]
    removed_refs: tuple[str, ...]
    rejected_refs: tuple[str, ...]
    warnings: tuple[PlanWarning, ...]


def _plan_admin_key_material(inputs: PlanInputs) -> _AdminKeyPlan:
    """Decide the desired ``security.admin_key`` set (step 6).

    See the module docstring for the exact rule this implements,
    including that an ``admin_nodes`` entry failing the weak-key audit is
    excluded from the desired set regardless of ``security.is_managed``,
    unless ``inputs.allow_weak_admin_key`` overrides that.

    Args:
        inputs: The plan inputs.

    Returns:
        The :class:`_AdminKeyPlan`, carrying the
        ``"live_admin_key_rejected"`` warnings for live keys dropped by
        the audit, ``"live_admin_key_revoked"`` warnings for live keys
        dropped only for being absent from a non-empty
        ``template.admin_nodes``, and, for template-named keys the audit
        flagged, either ``"resolved_admin_key_rejected"`` warnings or --
        under ``inputs.allow_weak_admin_key`` --
        ``"resolved_admin_key_forced"`` ones.

    Raises:
        AdminKeyCapacityError: If ``template.admin_nodes`` resolves to
            more keys than the firmware supports.
    """
    live_keys = inputs.live.security.admin_keys

    dropped_indices = [i for i, k in enumerate(live_keys) if k in inputs.rejected_admin_keys]
    kept = tuple(k for i, k in enumerate(live_keys) if i not in dropped_indices)
    removed = tuple(f"live-admin[{i}]" for i in dropped_indices)
    warnings = [
        PlanWarning(
            "live_admin_key_rejected",
            f"Live admin key {label} failed the weak-key audit and will be removed.",
            section="security",
            field="admin_key",
        )
        for label in removed
    ]

    rejected_refs: tuple[str, ...] = ()
    revoked: tuple[str, ...] = ()
    if not inputs.template.admin_nodes:
        desired = kept
        desired_refs: tuple[str, ...] = ()
    else:
        # The capacity check reads the pre-filter count on purpose: "the template
        # names more admins than the firmware holds" is a template error, and must
        # not start or stop being reported depending on the blocklist's contents.
        if len(inputs.admin_keys) > MAX_ADMIN_KEYS:
            raise AdminKeyCapacityError(
                f"Plan requires {len(inputs.admin_keys)} admin keys; the firmware supports "
                f"at most {MAX_ADMIN_KEYS}.",
                count=len(inputs.admin_keys),
                limit=MAX_ADMIN_KEYS,
            )
        weak = tuple(k for k in inputs.admin_keys if not k.audit_ok)
        if inputs.allow_weak_admin_key:
            authorized = inputs.admin_keys
            rejected: tuple[ResolvedAdminKey, ...] = ()
            warnings.extend(
                PlanWarning(
                    "resolved_admin_key_forced",
                    f"Admin key {key.key_ref} failed the weak-key audit but will be "
                    f"authorized anyway (--allow-weak-admin-key): "
                    f"{key.audit_summary or 'flagged as compromised'}.",
                    section="security",
                    field="admin_key",
                )
                for key in weak
            )
        else:
            authorized = tuple(k for k in inputs.admin_keys if k.audit_ok)
            rejected = weak
            warnings.extend(
                PlanWarning(
                    "resolved_admin_key_rejected",
                    f"Admin key {key.key_ref} failed the weak-key audit and will not be "
                    f"authorized: {key.audit_summary or 'flagged as compromised'}. Correct or "
                    f"replace that Keys sheet row (see `mesh admin import`).",
                    section="security",
                    field="admin_key",
                )
                for key in rejected
            )
        desired = tuple(k.public for k in authorized)
        desired_refs = tuple(k.key_ref for k in authorized)
        rejected_refs = tuple(k.key_ref for k in rejected)

        revoked_indices = [
            i for i, k in enumerate(live_keys) if i not in dropped_indices and k not in desired
        ]
        revoked = tuple(f"live-admin[{i}]" for i in revoked_indices)
        warnings.extend(
            PlanWarning(
                "live_admin_key_revoked",
                f"Live admin key {label} is authorized on the device but not named in "
                f"template.admin_nodes; it will be removed.",
                section="security",
                field="admin_key",
            )
            for label in revoked
        )

    return _AdminKeyPlan(
        desired=desired,
        desired_refs=desired_refs,
        change_admin_keys=sorted(desired) != sorted(live_keys),
        removed=removed,
        revoked=revoked,
        removed_refs=inputs.removed_admin_key_refs,
        rejected_refs=rejected_refs,
        warnings=tuple(warnings),
    )
