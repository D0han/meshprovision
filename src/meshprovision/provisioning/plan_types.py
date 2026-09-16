"""Pure data types for a change plan: no planning logic, just shape.

Split out of :mod:`meshprovision.provisioning.plan` (which was 3x the
project's ~400-line typical file size) along the same seam already used
for :mod:`~meshprovision.provisioning.plan_admin_keys`/
:mod:`~meshprovision.provisioning.plan_render`/
:mod:`~meshprovision.provisioning.plan_warnings`: everything here is a
self-contained dataclass/enum with no dependency on the ``_plan_*``
helpers or :func:`~meshprovision.provisioning.plan.build_plan` that
construct them -- only the reverse dependency exists. ``plan.py``
imports every name defined here and re-exports it in its own
``__all__`` unchanged, so no external caller needs to change which
module it imports from.

Same purity invariant as ``plan.py``: zero I/O, zero device access,
zero ``datetime.now()``, zero logging side effects, and it imports
nothing from ``meshtastic``, ``httpx``, ``pathlib``, ``odfpy``, or
:mod:`meshprovision.crypto`.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from meshprovision.provisioning import detect
from meshprovision.provisioning.plan_admin_keys import KeyPlan, ResolvedAdminKey
from meshprovision.provisioning.plan_warnings import PlanWarning

if TYPE_CHECKING:
    from collections.abc import Mapping

    from meshprovision.config.template import TemplateConfig
    from meshprovision.db.nodes import NodeRecord
    from meshprovision.nodeid import NodeId

__all__ = [
    "ChangePlan",
    "FieldChange",
    "LockdownDecision",
    "LockdownReason",
    "NameChange",
    "PlanInputs",
    "SectionChange",
    "values_equal",
]

_BLE_PIN_LENGTH: Final[int] = 6
"""Digit count of a BLE pairing PIN. Duplicates
:data:`meshprovision.db.schema.BLE_PIN_LENGTH`, which this module may not
import (see the module docstring's import restriction)."""


def values_equal(current: object, desired: object) -> bool:
    """Compare a live value against a desired value with type-tolerant semantics.

    Args:
        current: The value read from the live device.
        desired: The value the template wants.

    Returns:
        ``True`` when the two should be treated as equal. A ``bool`` on
        either side requires the other side to also be a ``bool`` (this
        guards against ``True == 1``); a ``float`` on either side (with
        both sides otherwise numeric) uses ``math.isclose`` with
        ``rel_tol=1e-9``/``abs_tol=1e-9``; everything else uses plain
        ``==``.
    """
    current_is_bool = isinstance(current, bool)
    desired_is_bool = isinstance(desired, bool)
    if current_is_bool or desired_is_bool:
        if current_is_bool != desired_is_bool:
            return False
        return current == desired
    if isinstance(current, int | float) and isinstance(desired, int | float):
        return math.isclose(float(current), float(desired), rel_tol=1e-9, abs_tol=1e-9)
    return current == desired


@dataclass(frozen=True, slots=True)
class FieldChange:
    """One field's current-vs-desired value, within a config section.

    Attributes:
        section: Name of the owning section.
        field: Name of the field within that section.
        current: The value read from the live device.
        desired: The value the plan intends to write.
        secret: Whether this field carries secret material. When
            ``True``, :meth:`describe` and :meth:`to_json_dict` never
            render :attr:`current`/:attr:`desired`.
        reason: Why this change is being made: ``"template"`` (the
            common case), ``"forced"`` (unconditional, independent of
            the template -- ``security.admin_channel_enabled``),
            ``"weak_key"``, ``"regenerate"``, or ``"adopt"``.
    """

    section: str
    field: str
    current: object
    desired: object
    secret: bool = False
    reason: str = "template"

    def describe(self) -> str:
        """Render this change as one redaction-safe, human-readable string.

        Returns:
            ``"<redacted> -> <redacted>"`` when :attr:`secret`; otherwise
            ``f"{current} -> {desired}"``.
        """
        if self.secret:
            return "<redacted> -> <redacted>"
        return f"{self.current} -> {self.desired}"

    def to_json_dict(self) -> dict[str, object]:
        """Render this change as a JSON-safe, redaction-safe dict.

        Returns:
            A dict with ``current``/``desired`` replaced by the literal
            string ``"<redacted>"`` when :attr:`secret`.
        """
        current: object = "<redacted>" if self.secret else self.current
        desired: object = "<redacted>" if self.secret else self.desired
        return {
            "section": self.section,
            "field": self.field,
            "current": current,
            "desired": desired,
            "secret": self.secret,
            "reason": self.reason,
        }

    def __repr__(self) -> str:
        """Return a repr that never exposes a secret field's raw value.

        Returns:
            The default-shaped dataclass repr, with :attr:`current` and
            :attr:`desired` replaced by ``<redacted>`` when
            :attr:`secret` is set.
        """
        if self.secret:
            return (
                f"FieldChange(section={self.section!r}, field={self.field!r}, "
                f"current=<redacted>, desired=<redacted>, secret=True, "
                f"reason={self.reason!r})"
            )
        return (
            f"FieldChange(section={self.section!r}, field={self.field!r}, "
            f"current={self.current!r}, desired={self.desired!r}, secret=False, "
            f"reason={self.reason!r})"
        )


@dataclass(frozen=True, slots=True)
class SectionChange:
    """A config or module-config section's field changes.

    Attributes:
        section: Name of the section.
        kind: Whether ``section`` names a ``LocalConfig`` field
            (:attr:`detect.SectionKind.CONFIG`) or a
            ``LocalModuleConfig`` field
            (:attr:`detect.SectionKind.MODULE_CONFIG`) -- see
            :meth:`detect.LiveConfig.kind_of`.
        changes: The field changes to apply, in a fixed order. May be
            empty even for a section :func:`~meshprovision.provisioning.plan.build_plan`
            includes in :attr:`ChangePlan.sections`, specifically for
            ``"security"`` when only key material (never represented as
            a :class:`FieldChange`) needs writing.
        reboots_device: Whether writing this section reboots the device.
            ``True`` for ``"lora"`` when ``region``/``modem_preset``
            changed, and always for ``"security"``.
    """

    section: str
    kind: detect.SectionKind
    changes: tuple[FieldChange, ...]
    reboots_device: bool = False

    @property
    def is_empty(self) -> bool:
        """Whether this section has no field changes.

        Returns:
            ``True`` if :attr:`changes` is empty. Note this can be
            ``True`` for a section still meaningfully present in
            :attr:`ChangePlan.sections` -- see :attr:`changes`.
        """
        return len(self.changes) == 0


@dataclass(frozen=True, slots=True)
class NameChange:
    """The device's ``short_name``/``long_name``, current vs. desired.

    Attributes:
        current_short_name: The live ``short_name``.
        desired_short_name: The ``short_name`` the plan intends.
        current_long_name: The live ``long_name``.
        desired_long_name: The ``long_name`` the plan intends.
    """

    current_short_name: str
    desired_short_name: str
    current_long_name: str
    desired_long_name: str

    @property
    def is_empty(self) -> bool:
        """Whether both names are already at their desired values.

        Returns:
            ``True`` if neither name differs.
        """
        return not self.short_changed and not self.long_changed

    @property
    def short_changed(self) -> bool:
        """Whether ``short_name`` needs to change.

        Returns:
            ``True`` if :attr:`current_short_name` differs from
            :attr:`desired_short_name`.
        """
        return self.current_short_name != self.desired_short_name

    @property
    def long_changed(self) -> bool:
        """Whether ``long_name`` needs to change.

        Returns:
            ``True`` if :attr:`current_long_name` differs from
            :attr:`desired_long_name`.
        """
        return self.current_long_name != self.desired_long_name


class LockdownReason(StrEnum):
    """Why a :class:`LockdownDecision` came out the way it did."""

    TEMPLATE_OPT_OUT = "template_opt_out"
    """The template does not request ``security.is_managed``."""

    AUTHORIZED = "authorized"
    """Every gate passed and ``--allow-lockdown`` was given."""

    ALREADY_LOCKED = "already_locked"
    """Every gate passed, the explicit opt-in flag was not given this
    run, but the live device is already locked down -- ``enable`` stays
    ``True`` so this run does not silently unlock it."""

    ALLOW_LOCKDOWN_NOT_SET = "allow_lockdown_not_set"
    """Every hard gate passed, the device is not yet locked, and the
    explicit opt-in flag was not given."""


@dataclass(frozen=True, slots=True)
class LockdownDecision:
    """The outcome of evaluating whether ``security.is_managed`` may be enabled.

    Attributes:
        enable: Whether ``is_managed`` should end up ``True``.
        reason: See :class:`LockdownReason`.
        gates: ``{"has_admin_keys": ..., "has_private_counterpart": ...,
            "audit_clean": ..., "explicit_intent": ...}``.
    """

    enable: bool
    reason: LockdownReason
    gates: Mapping[str, bool]


@dataclass(frozen=True, slots=True)
class PlanInputs:
    """Everything ``build_plan`` needs, already resolved by the caller.

    See :func:`meshprovision.provisioning.plan.build_plan`.

    Attributes:
        live: The device's normalized live configuration.
        template: The validated provisioning template.
        db_entry: The matching ``Nodes`` sheet row, or ``None`` if this
            node is not yet in the database.
        state: This node's classification, from
            :func:`meshprovision.provisioning.detect.classify`.
        admin_keys: The resolved, audited admin keys named in
            ``template.admin_nodes``, in template order.
        rejected_admin_keys: Live admin keys the caller's weak-key audit
            flagged for removal.
        removed_admin_key_refs: The subset of
            ``db_entry.authorized_admin_keys`` whose ``Keys`` sheet
            material appears in :attr:`rejected_admin_keys`, resolved by
            the caller (this module cannot map a ref to key material).
            Non-empty implies those keys are live on the device and this
            plan is removing them.
        desired_short_name: An externally allocated ``short_name``
            (e.g. from ``NodeRepository.next_free_name``), or ``None``
            to keep the database's (or, failing that, the device's)
            current name.
        desired_long_name: The ``long_name`` counterpart of
            :attr:`desired_short_name`.
        ble_pin: A freshly generated 6-ASCII-digit BLE pairing PIN, or
            ``None`` to leave Bluetooth pairing unplanned.
        node_key_compromised: Whether the caller's own audit flagged the
            device's current keypair as compromised, independent of the
            structural/firmware-window checks this module makes itself.
        node_key_reason: Human-readable reason for
            :attr:`node_key_compromised`, when set.
        db_public_key: This node's public key as recorded in the
            ``Keys`` sheet, when known.
        force_regenerate_key: Whether to regenerate the node keypair
            unconditionally (``--force-regenerate-key``).
        allow_lockdown: Whether the operator explicitly authorized
            enabling ``security.is_managed`` (``--allow-lockdown``).
        allow_weak_admin_key: Whether the operator explicitly authorized
            admin keys that fail the weak-key audit
            (``--allow-weak-admin-key``). Affects only the desired
            admin-key set; ``_evaluate_lockdown``'s hard refusal is
            deliberately not relaxed by it.
    """

    live: detect.LiveConfig
    template: TemplateConfig
    db_entry: NodeRecord | None = None
    state: detect.NodeState = detect.NodeState.FACTORY
    admin_keys: tuple[ResolvedAdminKey, ...] = ()
    rejected_admin_keys: frozenset[bytes] = frozenset()
    removed_admin_key_refs: tuple[str, ...] = ()
    desired_short_name: str | None = None
    desired_long_name: str | None = None
    ble_pin: str | None = None
    node_key_compromised: bool = False
    node_key_reason: str = ""
    db_public_key: bytes | None = None
    force_regenerate_key: bool = False
    allow_lockdown: bool = False
    allow_weak_admin_key: bool = False

    def __repr__(self) -> str:
        """Return a repr that never exposes :attr:`ble_pin` or :attr:`db_public_key`.

        Returns:
            The default-shaped dataclass repr, with :attr:`ble_pin`
            replaced by ``<redacted>`` (when set) and
            :attr:`db_public_key` replaced by ``<redacted>`` (when set).
        """
        ble_pin_repr = "<redacted>" if self.ble_pin is not None else None
        db_key_repr = "<redacted>" if self.db_public_key is not None else None
        return (
            f"PlanInputs(live={self.live!r}, template={self.template!r}, "
            f"db_entry={self.db_entry!r}, state={self.state!r}, "
            f"admin_keys={self.admin_keys!r}, "
            f"rejected_admin_keys=<{len(self.rejected_admin_keys)} redacted key(s)>, "
            f"removed_admin_key_refs={self.removed_admin_key_refs!r}, "
            f"desired_short_name={self.desired_short_name!r}, "
            f"desired_long_name={self.desired_long_name!r}, ble_pin={ble_pin_repr!r}, "
            f"node_key_compromised={self.node_key_compromised!r}, "
            f"node_key_reason={self.node_key_reason!r}, db_public_key={db_key_repr!r}, "
            f"force_regenerate_key={self.force_regenerate_key!r}, "
            f"allow_lockdown={self.allow_lockdown!r}, "
            f"allow_weak_admin_key={self.allow_weak_admin_key!r})"
        )


@dataclass(frozen=True, slots=True)
class ChangePlan:
    """The exact, deterministic plan :mod:`~meshprovision.provisioning.apply` executes.

    Beyond the fields the design brief specifies, this carries four small
    extra fields (:attr:`hw_model`, :attr:`firmware_version`, :attr:`role`,
    :attr:`region`) plus :attr:`db_entry`, all copied through from the
    :class:`PlanInputs` that built this plan. They exist solely so
    :meth:`to_record` can build a complete row without its caller having
    to re-supply the live/template state -- ``apply.py`` calls
    ``plan.to_record()`` with no arguments, so the plan must be able to
    answer that on its own. None of them carry secret material.

    Attributes:
        node_id: The node this plan targets.
        state: The node's classification at plan time.
        is_new: Whether this node was absent from the database.
        name_change: The ``short_name``/``long_name`` change.
        sections: Every non-empty config/module-config section change,
            already in final execution order (see
            :data:`~meshprovision.provisioning.plan.SECTION_ORDER`).
        key_plan: The node-keypair and admin-key decisions.
        lockdown: The ``security.is_managed`` decision.
        warnings: Non-fatal findings, in a fixed order.
        ble_pin_set: Whether a Bluetooth PIN change is part of this plan.
        hw_model: The live hardware model, carried through for
            :meth:`to_record`.
        firmware_version: The live firmware version, carried through for
            :meth:`to_record`.
        role: The template's intended ``device.role``, carried through
            for :meth:`to_record`.
        region: The template's intended ``lora.region``, carried through
            for :meth:`to_record`.
        db_entry: The database row this plan was built against, used as
            :meth:`to_record`'s default baseline.
    """

    node_id: NodeId
    state: detect.NodeState
    is_new: bool
    name_change: NameChange
    sections: tuple[SectionChange, ...]
    key_plan: KeyPlan
    lockdown: LockdownDecision
    warnings: tuple[PlanWarning, ...] = ()
    ble_pin_set: bool = False
    hw_model: str = ""
    firmware_version: str = ""
    role: str = ""
    region: str = ""
    db_entry: NodeRecord | None = None

    @property
    def is_empty(self) -> bool:
        """Whether this plan has nothing at all to do.

        Returns:
            ``True`` if the name is unchanged, every section is empty,
            and the key plan is empty.
        """
        return (
            self.name_change.is_empty
            and all(section.is_empty for section in self.sections)
            and self.key_plan.is_empty
        )

    @property
    def reboots_device(self) -> bool:
        """Whether executing this plan reboots the device.

        Returns:
            ``True`` if any section in :attr:`sections` has
            ``reboots_device`` set.
        """
        return any(section.reboots_device for section in self.sections)

    def section(self, name: str) -> SectionChange | None:
        """Look up one section's change by name.

        Args:
            name: The section name to look up.

        Returns:
            The matching :class:`SectionChange`, or ``None`` if
            :attr:`sections` has no entry for ``name``.
        """
        for section in self.sections:
            if section.section == name:
                return section
        return None

    def describe(self) -> tuple[str, ...]:
        """Render this plan as ready-to-print ``--dry-run`` lines.

        Returns:
            One already-redacted line per name change, per field change,
            and per key-plan decision. Never renders raw key material or
            a raw BLE PIN.
        """
        lines: list[str] = []
        if self.name_change.short_changed:
            lines.append(
                f"owner.short_name: {self.name_change.current_short_name!r} -> "
                f"{self.name_change.desired_short_name!r}"
            )
        if self.name_change.long_changed:
            lines.append(
                f"owner.long_name: {self.name_change.current_long_name!r} -> "
                f"{self.name_change.desired_long_name!r}"
            )
        for section in self.sections:
            for change in section.changes:
                lines.append(f"{section.section}.{change.field}: {change.describe()}")
        if self.key_plan.regenerate:
            reason = (
                f" ({self.key_plan.regenerate_reason})" if self.key_plan.regenerate_reason else ""
            )
            lines.append(f"security.private_key: regenerate{reason}")
        if self.key_plan.adopt_device_key:
            lines.append("security.public_key: adopt the device's reported key")
        if self.key_plan.change_admin_keys:
            refs = ", ".join(self.key_plan.desired_admin_key_refs) or "<none>"
            lines.append(f"security.admin_key: authorize [{refs}]")
        if self.key_plan.removed_admin_fingerprints:
            removed = ", ".join(self.key_plan.removed_admin_fingerprints)
            lines.append(f"security.admin_key: remove [{removed}] (weak-key audit)")
        if self.key_plan.revoked_admin_fingerprints:
            revoked = ", ".join(self.key_plan.revoked_admin_fingerprints)
            lines.append(f"security.admin_key: revoke [{revoked}] (not in template.admin_nodes)")
        # Deliberately its own top-level guard, not nested under change_admin_keys:
        # when every named admin key is refused and none was live, desired and live
        # are both empty, so change_admin_keys is False in exactly the case the
        # operator most needs to see this line.
        if self.key_plan.rejected_admin_key_refs:
            refused = ", ".join(self.key_plan.rejected_admin_key_refs)
            lines.append(f"security.admin_key: refuse [{refused}] (weak-key audit)")
        return tuple(lines)

    def summary(self) -> str:
        """Render a one-line summary of this plan.

        Returns:
            For example ``"3 sections, 7 fields, keys: regenerate, admin: 2"``.
        """
        section_count = len(self.sections)
        field_count = sum(len(section.changes) for section in self.sections)
        parts = [
            f"{section_count} section{'s' if section_count != 1 else ''}",
            f"{field_count} field{'s' if field_count != 1 else ''}",
        ]
        key_bits: list[str] = []
        if self.key_plan.regenerate:
            key_bits.append("regenerate")
        if self.key_plan.adopt_device_key:
            key_bits.append("adopt")
        if key_bits:
            parts.append(f"keys: {', '.join(key_bits)}")
        if self.key_plan.change_admin_keys:
            parts.append(f"admin: {len(self.key_plan.desired_admin_keys)}")
        return ", ".join(parts)

    def to_json_dict(self) -> dict[str, object]:
        """Render this plan as a JSON-safe, redaction-safe, deterministic dict.

        Returns:
            The full plan structure, suitable for ``--dry-run --json``.
            Identical plans produce byte-identical output.
        """
        return {
            "node_id": self.node_id.hex,
            "state": self.state.value,
            "is_new": self.is_new,
            "name_change": {
                "current_short_name": self.name_change.current_short_name,
                "desired_short_name": self.name_change.desired_short_name,
                "current_long_name": self.name_change.current_long_name,
                "desired_long_name": self.name_change.desired_long_name,
            },
            "sections": [
                {
                    "section": section.section,
                    "kind": section.kind,
                    "reboots_device": section.reboots_device,
                    "changes": [change.to_json_dict() for change in section.changes],
                }
                for section in self.sections
            ],
            "key_plan": {
                "regenerate": self.key_plan.regenerate,
                "regenerate_reason": self.key_plan.regenerate_reason,
                "adopt_device_key": self.key_plan.adopt_device_key,
                "change_admin_keys": self.key_plan.change_admin_keys,
                "admin_key_count": len(self.key_plan.desired_admin_keys),
                "desired_admin_key_refs": list(self.key_plan.desired_admin_key_refs),
                "removed_admin_fingerprints": list(self.key_plan.removed_admin_fingerprints),
                "revoked_admin_fingerprints": list(self.key_plan.revoked_admin_fingerprints),
                "removed_admin_key_refs": list(self.key_plan.removed_admin_key_refs),
                "rejected_admin_key_refs": list(self.key_plan.rejected_admin_key_refs),
            },
            "lockdown": {
                "enable": self.lockdown.enable,
                "reason": self.lockdown.reason,
                "gates": dict(self.lockdown.gates),
            },
            "warnings": [w.to_json_dict() for w in self.warnings],
            "ble_pin_set": self.ble_pin_set,
        }

    def to_record(
        self,
        *,
        existing: NodeRecord | None = None,
        confirmed_short_name: str | None = None,
        confirmed_long_name: str | None = None,
    ) -> NodeRecord:
        """Build the ``Nodes`` sheet row this plan intends to persist.

        Pure: builds a new, fully re-validated record and never mutates
        ``existing`` or :attr:`db_entry`.

        Args:
            existing: The row to start from. Defaults to :attr:`db_entry`
                (the row :func:`~meshprovision.provisioning.plan.build_plan`
                was given), and falls back to a fresh record for this
                node id when neither is set.
            confirmed_short_name: The short name actually confirmed on the
                device after a real (non-dry-run) apply, when firmware
                truncated it -- overrides :attr:`name_change`'s desired
                value so the record matches what the device really holds,
                not what was asked for. ``None`` (the default, and always
                for a dry-run preview) keeps the desired value.
            confirmed_long_name: The long-name counterpart of
                ``confirmed_short_name``.

        Returns:
            The new :class:`~meshprovision.db.nodes.NodeRecord`.
            ``authorized_admin_keys`` is left untouched (preserving
            whatever ``existing`` already had) when :attr:`key_plan` has
            neither ``desired_admin_key_refs`` nor
            ``rejected_admin_key_refs``, since an empty ``admin_nodes``
            template means "no opinion," never "clear the refs." When
            every named ref was instead *rejected* by the weak-key audit
            the refs are cleared to ``()``, because the device really
            does end up holding no authorized admin key and the old row
            would otherwise keep asserting a key this plan just refused.
            Failing both, any ref named in
            :attr:`KeyPlan.removed_admin_key_refs` is subtracted from
            ``existing``: the "no opinion" template still may not keep
            asserting a live key the weak-key audit just revoked. The row
            is only ever narrowed on that path, never rebuilt.
            ``ble_pin`` is set only when :attr:`ble_pin_set`. ``management``
            is always set to :attr:`~meshprovision.db.schema.ManagementMode.TEMPLATE`
            in the returned record, since reaching this point means the
            plan is being applied under full template management (whether
            newly enrolled or already there).
        """
        from meshprovision.db.nodes import NodeRecord as _NodeRecord
        from meshprovision.db.schema import ManagementMode

        base = existing if existing is not None else self.db_entry
        if base is None:
            base = _NodeRecord(node_id=self.node_id.hex)

        changes: dict[str, object] = {
            "short_name": (
                confirmed_short_name
                if confirmed_short_name is not None
                else self.name_change.desired_short_name
            ),
            "long_name": (
                confirmed_long_name
                if confirmed_long_name is not None
                else self.name_change.desired_long_name
            ),
            "hw_model": self.hw_model,
            "firmware_version": self.firmware_version,
            "role": self.role,
            "region": self.region,
            "management": ManagementMode.TEMPLATE,
        }
        if self.key_plan.desired_admin_key_refs or self.key_plan.rejected_admin_key_refs:
            changes["authorized_admin_keys"] = self.key_plan.desired_admin_key_refs
        elif self.key_plan.removed_admin_key_refs:
            dropped = frozenset(self.key_plan.removed_admin_key_refs)
            changes["authorized_admin_keys"] = tuple(
                ref for ref in base.authorized_admin_keys if ref not in dropped
            )

        if self.ble_pin_set:
            bluetooth = self.section("bluetooth")
            pin_change = (
                next((c for c in bluetooth.changes if c.field == "fixed_pin"), None)
                if bluetooth is not None
                else None
            )
            if pin_change is not None:
                changes["ble_pin"] = str(pin_change.desired).zfill(_BLE_PIN_LENGTH)

        return base.with_updates(**changes)
