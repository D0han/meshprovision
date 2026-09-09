"""Pure change-plan computation: ``(live_config, template, db_entry) -> ChangePlan``.

This module is **strictly pure**: zero I/O, zero device access, zero
``datetime.now()``, zero logging side effects, and it imports nothing
from ``meshtastic``, ``httpx``, ``pathlib``, ``odfpy``, or
:mod:`meshprovision.crypto`. :func:`build_plan` turns an already-read
:class:`~meshprovision.provisioning.detect.LiveConfig`, an already-loaded
:class:`~meshprovision.config.template.TemplateConfig`, an optional
:class:`~meshprovision.db.nodes.NodeRecord`, and pre-resolved admin keys
into an exact, deterministic, orderable :class:`ChangePlan` --
:mod:`meshprovision.provisioning.apply` executes it field-for-field, and
``mesh provision --dry-run`` prints it verbatim. Purity is what makes
``--dry-run`` an *exact* preview rather than an approximation, and it is
where the bulk of this project's unit-test coverage lands.

Given identical inputs, :func:`build_plan` produces byte-identical
:meth:`ChangePlan.to_json_dict` output: no iteration over an unsorted
``set``, no reliance on ``dict`` insertion order beyond the fixed
:data:`SECTION_ORDER`, and no input is ever mutated (every input is
already frozen; this module never calls ``.append`` on one).

**The admin-key rule** lives with the code that implements it, in
:mod:`meshprovision.provisioning.plan_admin_keys` -- see that module's docstring
for the exact rule :func:`build_plan` applies to ``template.admin_nodes``,
``security.admin_key``, and ``--allow-weak-admin-key``.

Secret hygiene: this module never imports :mod:`meshprovision.crypto`
(digests are the caller's job), yet it still never lets raw key bytes
reach a ``repr()``: :class:`ResolvedAdminKey` reuses its own
caller-supplied ``fingerprint`` field, and :class:`KeyPlan` and
:class:`FieldChange` render a fixed ``<redacted>`` placeholder for any
secret material in their custom ``__repr__``/``describe``/
``to_json_dict``. Dropped live admin keys are named only as positional
labels (``"live-admin[0]"``, ...), never fingerprinted, since computing
a digest would require :mod:`hashlib` -- ``apply.py``/the render layer
resolve a real fingerprint for those, downstream of this module.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

from meshprovision.config.template import LONG_NAME_MAX_BYTES, SHORT_NAME_MAX_BYTES
from meshprovision.errors import LockdownRefusedError
from meshprovision.provisioning import detect
from meshprovision.provisioning.plan_admin_keys import (
    KeyPlan,
    ResolvedAdminKey,
    _plan_admin_key_material,
)
from meshprovision.provisioning.plan_warnings import PlanWarning, PlanWarningCode

if TYPE_CHECKING:
    from collections.abc import Mapping

    from meshprovision.config.template import TemplateConfig
    from meshprovision.db.nodes import NodeRecord
    from meshprovision.nodeid import NodeId

__all__ = [
    "MODULE_ENABLED_FIELD",
    "SECTION_ORDER",
    "ChangePlan",
    "FieldChange",
    "LockdownDecision",
    "LockdownReason",
    "NameChange",
    "PlanInputs",
    "PlanWarning",
    "PlanWarningCode",
    "SectionChange",
    "build_plan",
    "values_equal",
]

MODULE_ENABLED_FIELD: Final[str] = "enabled"
"""The field name every module-config diff writes its on/off state under."""

SECTION_ORDER: Final[tuple[str, ...]] = (
    "device",
    "position",
    "power",
    "lora",
    "bluetooth",
    "security",
)
"""The config-section write order. ``"security"`` is always last: writing
``is_managed=true`` can lock the node against any further write, so every
other section must land first. Module sections are written after these
(in sorted-name order) but before ``"security"`` -- :func:`build_plan`
emits :attr:`ChangePlan.sections` already in this final execution order,
so :mod:`meshprovision.provisioning.apply` just iterates it."""

_POSITION_FIXED_FIELDS: Final[frozenset[str]] = frozenset(
    {"fixed_latitude", "fixed_longitude", "fixed_altitude"}
)
"""``PositionSection`` keys that are not ``PositionConfig`` fields at all --
they go through the device's fixed-position API, handled by the caller,
never diffed here."""

_REBOOT_LORA_FIELDS: Final[frozenset[str]] = frozenset({"region", "modem_preset"})
"""``lora`` fields whose change reboots the device."""

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
            empty even for a section :func:`build_plan` includes in
            :attr:`ChangePlan.sections`, specifically for
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

    def field_names(self) -> tuple[str, ...]:
        """Return the name of every changed field, in order.

        Returns:
            ``tuple(c.field for c in self.changes)``.
        """
        return tuple(change.field for change in self.changes)


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
    """Everything :func:`build_plan` needs, already resolved by the caller.

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
            admin-key set; :func:`_evaluate_lockdown`'s hard refusal is
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
            already in final execution order (see :data:`SECTION_ORDER`).
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
                (the row :func:`build_plan` was given), and falls back to
                a fresh record for this node id when neither is set.
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


def _plan_name_change(inputs: PlanInputs) -> NameChange:
    """Resolve the desired ``short_name``/``long_name`` (step 1).

    Args:
        inputs: The plan inputs.

    Returns:
        The :class:`NameChange`, computed from
        ``inputs.desired_short_name``/``desired_long_name`` when set,
        else the database entry's name when non-empty, else the live
        name.
    """
    live = inputs.live
    db_entry = inputs.db_entry

    desired_short = inputs.desired_short_name
    if desired_short is None:
        desired_short = db_entry.short_name if db_entry and db_entry.short_name else live.short_name

    desired_long = inputs.desired_long_name
    if desired_long is None:
        desired_long = db_entry.long_name if db_entry and db_entry.long_name else live.long_name

    return NameChange(
        current_short_name=live.short_name,
        desired_short_name=desired_short,
        current_long_name=live.long_name,
        desired_long_name=desired_long,
    )


def _name_warnings(name_change: NameChange) -> tuple[PlanWarning, ...]:
    """Check a desired name against its firmware byte limit.

    Args:
        name_change: The resolved name change.

    Returns:
        A ``"name_truncation_risk"`` warning per name that overflows its
        limit. This never raises -- the template validator already
        guards the common case; this catches a hand-passed name.
    """
    warnings: list[PlanWarning] = []
    short_bytes = len(name_change.desired_short_name.encode("utf-8"))
    if short_bytes > SHORT_NAME_MAX_BYTES:
        warnings.append(
            PlanWarning(
                PlanWarningCode.NAME_TRUNCATION_RISK,
                f"Desired short_name {name_change.desired_short_name!r} is {short_bytes} "
                f"UTF-8 bytes, over the {SHORT_NAME_MAX_BYTES}-byte firmware limit, and "
                "will be truncated silently.",
                field="short_name",
            )
        )
    long_bytes = len(name_change.desired_long_name.encode("utf-8"))
    if long_bytes > LONG_NAME_MAX_BYTES:
        warnings.append(
            PlanWarning(
                PlanWarningCode.NAME_TRUNCATION_RISK,
                f"Desired long_name {name_change.desired_long_name!r} is {long_bytes} "
                f"UTF-8 bytes, over the {LONG_NAME_MAX_BYTES}-byte firmware limit, and "
                "will be truncated silently.",
                field="long_name",
            )
        )
    return tuple(warnings)


def _diff_section(
    section_name: str, model: Any, live: detect.LiveConfig
) -> tuple[FieldChange, ...]:
    """Diff one template section model against the live device state.

    Args:
        section_name: The section name, used both to read the template
            model's dumped fields and to look up the live value.
        model: The template's pydantic section model (for example
            ``template.device``).
        live: The device's live configuration.

    Returns:
        One :class:`FieldChange` per field whose template value differs
        from the live value, in the model's own field-declaration order.
        For ``"position"``, the fixed-position fields in
        :data:`_POSITION_FIXED_FIELDS` are skipped -- they are not
        ``PositionConfig`` fields at all.
    """
    changes: list[FieldChange] = []
    for field_name, desired_value in model.model_dump(exclude_none=True).items():
        if section_name == "position" and field_name in _POSITION_FIXED_FIELDS:
            continue
        current_value = live.value(section_name, field_name)
        if not values_equal(current_value, desired_value):
            changes.append(
                FieldChange(
                    section=section_name,
                    field=field_name,
                    current=current_value,
                    desired=desired_value,
                )
            )
    return tuple(changes)


def _plan_config_sections(
    inputs: PlanInputs,
) -> tuple[tuple[SectionChange, ...], tuple[PlanWarning, ...]]:
    """Diff the ``device``/``position``/``power``/``lora`` sections (step 2).

    Args:
        inputs: The plan inputs.

    Returns:
        The non-empty sections, in :data:`SECTION_ORDER` order, plus a
        ``"region_change_reboots"`` warning when ``lora.region`` or
        ``lora.modem_preset`` changed.
    """
    live = inputs.live
    template = inputs.template
    sections: list[SectionChange] = []
    warnings: list[PlanWarning] = []

    for section_name, model in (
        ("device", template.device),
        ("position", template.position),
        ("power", template.power),
        ("lora", template.lora),
    ):
        changes = _diff_section(section_name, model, live)
        if not changes:
            continue
        reboots = section_name == "lora" and any(c.field in _REBOOT_LORA_FIELDS for c in changes)
        if reboots:
            warnings.append(
                PlanWarning(
                    PlanWarningCode.REGION_CHANGE_REBOOTS,
                    "Changing lora.region/modem_preset reboots the device.",
                    section="lora",
                )
            )
        sections.append(
            SectionChange(
                section=section_name,
                kind=live.kind_of(section_name),
                changes=changes,
                reboots_device=reboots,
            )
        )

    return tuple(sections), tuple(warnings)


def _plan_module_sections(
    inputs: PlanInputs,
) -> tuple[tuple[SectionChange, ...], tuple[PlanWarning, ...]]:
    """Diff the module-option toggles and telemetry fields (steps 3-4).

    Args:
        inputs: The plan inputs.

    Returns:
        The non-empty module sections, sorted by name, plus any
        ``"unknown_module"``/``"module_has_no_enabled_field"`` warnings.
    """
    live = inputs.live
    template = inputs.template
    warnings: list[PlanWarning] = []
    module_changes: dict[str, SectionChange] = {}

    for opt, want in sorted(template.option_state().items()):
        if opt not in detect.MODULE_SECTIONS:
            warnings.append(
                PlanWarning(
                    PlanWarningCode.UNKNOWN_MODULE,
                    f"{opt!r} is not a known module section.",
                    section=opt,
                )
            )
            continue
        current = live.module_enabled.get(opt)
        if current is None:
            warnings.append(
                PlanWarning(
                    PlanWarningCode.MODULE_HAS_NO_ENABLED_FIELD,
                    f"Module {opt!r} has no 'enabled' field on this firmware.",
                    section=opt,
                )
            )
            continue
        if current != want:
            module_changes[opt] = SectionChange(
                section=opt,
                kind=live.kind_of(opt),
                changes=(
                    FieldChange(
                        section=opt, field=MODULE_ENABLED_FIELD, current=current, desired=want
                    ),
                ),
            )

    telemetry_changes = _diff_section("telemetry", template.telemetry, live)
    if telemetry_changes:
        module_changes["telemetry"] = SectionChange(
            section="telemetry", kind=live.kind_of("telemetry"), changes=telemetry_changes
        )

    ordered = tuple(module_changes[name] for name in sorted(module_changes))
    return ordered, tuple(warnings)


def _plan_bluetooth_section(inputs: PlanInputs) -> SectionChange | None:
    """Diff the Bluetooth fixed-PIN fields (step 5).

    Args:
        inputs: The plan inputs.

    Returns:
        ``None`` when ``inputs.ble_pin`` is ``None`` or nothing differs;
        otherwise a ``"bluetooth"`` :class:`SectionChange` whose
        ``fixed_pin`` :class:`FieldChange` always has ``secret=True``.
    """
    if inputs.ble_pin is None:
        return None
    live = inputs.live
    desired_fields: dict[str, object] = {
        "enabled": True,
        "mode": "FIXED_PIN",
        "fixed_pin": int(inputs.ble_pin),
    }
    changes: list[FieldChange] = []
    for field_name, desired_value in desired_fields.items():
        current_value = live.value("bluetooth", field_name)
        if not values_equal(current_value, desired_value):
            changes.append(
                FieldChange(
                    section="bluetooth",
                    field=field_name,
                    current=current_value,
                    desired=desired_value,
                    secret=("bluetooth", field_name) in detect.SECRET_FIELDS,
                )
            )
    if not changes:
        return None
    return SectionChange(
        section="bluetooth", kind=live.kind_of("bluetooth"), changes=tuple(changes)
    )


def _plan_node_keypair(inputs: PlanInputs) -> tuple[bool, str, bool, tuple[PlanWarning, ...]]:
    """Decide whether to regenerate the node keypair, or adopt the device's (step 7).

    Args:
        inputs: The plan inputs.

    Returns:
        A 4-tuple: whether to regenerate, the regenerate reason (empty
        when not regenerating), whether to adopt the device's reported
        public key into the database instead, and any
        ``"device_key_differs_from_db"`` warning.
    """
    live_sec = inputs.live.security

    if inputs.force_regenerate_key:
        return True, "forced", False, ()
    if inputs.state is detect.NodeState.FACTORY:
        return True, "factory_key_presumed_compromised", False, ()
    if not live_sec.has_public_key or not live_sec.has_private_key:
        return True, "missing_key_material", False, ()
    if inputs.node_key_compromised:
        return True, inputs.node_key_reason or "weak_key_audit", False, ()

    if inputs.db_public_key is not None and inputs.db_public_key != live_sec.public_key:
        warning = PlanWarning(
            PlanWarningCode.DEVICE_KEY_DIFFERS_FROM_DB,
            "The device's reported public key differs from the Keys sheet; adopting the "
            "device's key rather than overwriting it (firmware issue #7449).",
            section="security",
            field="public_key",
        )
        return False, "", True, (warning,)

    return False, "", False, ()


def _evaluate_lockdown(
    inputs: PlanInputs, desired_admin_keys: tuple[bytes, ...]
) -> LockdownDecision:
    """Decide whether ``security.is_managed`` may be enabled (step 9).

    Args:
        inputs: The plan inputs.
        desired_admin_keys: The desired admin-key set computed by
            :func:`meshprovision.provisioning.plan_admin_keys._plan_admin_key_material`.

    Returns:
        The :class:`LockdownDecision`.

    Raises:
        LockdownRefusedError: If the template opts into ``is_managed``
            but zero admin keys would be authorized, any authorized key's
            private counterpart does not correspond to its public key,
            none of the authorized keys has its private counterpart on
            hand, or any authorized key fails the weak-key audit. These
            are hard refusals: they are the "lock yourself out" and "lock
            with a compromised key" cases. The weak-key audit is checked
            first, so a key that is both compromised and mismatched is
            reported as ``"weak_admin_key"``.

    Note:
        ``--allow-lockdown`` gates only the *disabled -> enabled*
        transition. When the live device is already locked down
        (``inputs.live.security.is_managed`` is ``True``) and every
        hard gate above still passes, this returns ``enable=True``
        regardless of ``inputs.allow_lockdown`` -- an operator who
        forgets to repeat ``--allow-lockdown`` on a later, unrelated
        re-run must never have this function plan to *disable* an
        admin lockdown that was deliberately enabled earlier.
    """
    if not inputs.template.security.is_managed:
        gates = MappingProxyType(
            {
                "has_admin_keys": bool(desired_admin_keys),
                "has_private_counterpart": any(k.has_private for k in inputs.admin_keys),
                "audit_clean": all(k.audit_ok for k in inputs.admin_keys),
                "explicit_intent": inputs.allow_lockdown,
            }
        )
        return LockdownDecision(enable=False, reason=LockdownReason.TEMPLATE_OPT_OUT, gates=gates)

    # Must precede the emptiness gate below: a fully compromised admin_nodes list
    # filters down to desired_admin_keys == () in plan_admin_keys._plan_admin_key_material, which
    # would otherwise be refused as "no_admin_keys" and hide the real cause. This
    # reads the unfiltered inputs.admin_keys for exactly that reason.
    weak_refs = tuple(k.key_ref for k in inputs.admin_keys if not k.audit_ok)
    if weak_refs:
        raise LockdownRefusedError(
            f"Authorized admin key(s) failed the weak-key audit: {', '.join(weak_refs)}.",
            reason="weak_admin_key",
            hint="Replace the offending key(s) (see `mesh admin import`) and re-run.",
        )
    if not desired_admin_keys:
        raise LockdownRefusedError(
            "is_managed=true with zero authorized admin keys would lock the node with "
            "nobody able to administer it.",
            reason="no_admin_keys",
            hint=(
                "Add 1-3 refs to admin_nodes and register them with `mesh admin bootstrap` "
                "/ `mesh admin import`, or set security.is_managed to false."
            ),
        )
    mismatched = tuple(k.key_ref for k in inputs.admin_keys if k.private_mismatch)
    if mismatched:
        raise LockdownRefusedError(
            f"Admin key(s) have a private counterpart that does not match the "
            f"registered public key: {', '.join(mismatched)}.",
            reason="private_key_mismatch",
            hint=(
                "The _priv row exists but derives a different public key -- most often a "
                "half-finished rotation or a paste from another admin's backup. Correct "
                "the _priv value (or re-run `mesh admin bootstrap`) before locking down."
            ),
        )
    if not any(k.has_private for k in inputs.admin_keys):
        raise LockdownRefusedError(
            "None of the authorized admin keys has its private counterpart in the Keys sheet.",
            reason="no_private_counterpart",
            hint=(
                "At least one authorized admin key must have its private counterpart in "
                "the Keys sheet."
            ),
        )
    gates = MappingProxyType(
        {
            "has_admin_keys": True,
            "has_private_counterpart": True,
            "audit_clean": True,
            "explicit_intent": inputs.allow_lockdown,
        }
    )
    if not inputs.allow_lockdown:
        if inputs.live.security.is_managed:
            return LockdownDecision(enable=True, reason=LockdownReason.ALREADY_LOCKED, gates=gates)
        return LockdownDecision(
            enable=False, reason=LockdownReason.ALLOW_LOCKDOWN_NOT_SET, gates=gates
        )
    return LockdownDecision(enable=True, reason=LockdownReason.AUTHORIZED, gates=gates)


def _plan_security_section(
    inputs: PlanInputs, key_plan: KeyPlan, lockdown: LockdownDecision
) -> SectionChange | None:
    """Diff the ``security`` scalar fields and fold in pending key writes (step 8).

    Args:
        inputs: The plan inputs.
        key_plan: The already-decided key plan.
        lockdown: The already-decided lockdown decision.

    Returns:
        ``None`` when neither a scalar field nor any key material needs
        writing. Otherwise a ``"security"`` :class:`SectionChange` with
        ``reboots_device=True`` -- included even with an empty
        ``changes`` tuple when only key material (never represented as
        a :class:`FieldChange`) needs writing, since
        :mod:`meshprovision.provisioning.apply` only writes a section
        that is present in :attr:`ChangePlan.sections`.
    """
    live_sec = inputs.live.security
    template_sec = inputs.template.security

    desired: dict[str, bool] = {"admin_channel_enabled": False}
    current: dict[str, bool | None] = {"admin_channel_enabled": live_sec.admin_channel_enabled}

    if template_sec.serial_enabled is not None:
        desired["serial_enabled"] = template_sec.serial_enabled
        current["serial_enabled"] = live_sec.serial_enabled
    if template_sec.debug_log_api_enabled is not None:
        desired["debug_log_api_enabled"] = template_sec.debug_log_api_enabled
        current["debug_log_api_enabled"] = live_sec.debug_log_api_enabled

    desired["is_managed"] = lockdown.enable
    current["is_managed"] = live_sec.is_managed

    changes: list[FieldChange] = []
    for field_name, desired_value in desired.items():
        current_value = current[field_name]
        if not values_equal(current_value, desired_value):
            reason = "forced" if field_name == "admin_channel_enabled" else "template"
            changes.append(
                FieldChange(
                    section="security",
                    field=field_name,
                    current=current_value,
                    desired=desired_value,
                    reason=reason,
                )
            )

    if not changes and key_plan.is_empty:
        return None
    return SectionChange(
        section="security",
        kind=inputs.live.kind_of("security"),
        changes=tuple(changes),
        reboots_device=True,
    )


def _assemble_sections(
    config_sections: tuple[SectionChange, ...],
    module_sections: tuple[SectionChange, ...],
    bluetooth_section: SectionChange | None,
    security_section: SectionChange | None,
) -> tuple[SectionChange, ...]:
    """Combine every section into final execution order (step 10).

    Args:
        config_sections: The ``device``/``position``/``power``/``lora``
            sections, already in that order.
        module_sections: The module sections, already sorted by name.
        bluetooth_section: The Bluetooth section, or ``None``.
        security_section: The security section, or ``None``.

    Returns:
        ``config_sections``, then ``bluetooth_section`` (its
        :data:`SECTION_ORDER` position, right after ``lora``), then
        ``module_sections``, then ``security_section`` last.
    """
    ordered: list[SectionChange] = list(config_sections)
    if bluetooth_section is not None:
        ordered.append(bluetooth_section)
    ordered.extend(module_sections)
    if security_section is not None:
        ordered.append(security_section)
    return tuple(ordered)


def build_plan(inputs: PlanInputs) -> ChangePlan:
    """Build an exact, deterministic :class:`ChangePlan` from resolved inputs.

    Pure: no I/O, no device access, no clock reads. See the module
    docstring for the full purity contract and the admin-key rule.

    Args:
        inputs: Every already-resolved input this plan needs.

    Returns:
        The complete :class:`ChangePlan`.

    Raises:
        AdminKeyCapacityError: If ``template.admin_nodes`` resolves to
            more admin keys than the firmware supports.
        LockdownRefusedError: If the template opts into
            ``security.is_managed`` but the safety gates are not
            satisfied (zero admin keys, no private counterpart on hand,
            or a key fails the weak-key audit).
    """
    live = inputs.live
    template = inputs.template
    warnings: list[PlanWarning] = []

    name_change = _plan_name_change(inputs)
    warnings.extend(_name_warnings(name_change))

    config_sections, config_warnings = _plan_config_sections(inputs)
    warnings.extend(config_warnings)

    module_sections, module_warnings = _plan_module_sections(inputs)
    warnings.extend(module_warnings)

    bluetooth_section = _plan_bluetooth_section(inputs)

    admin_plan = _plan_admin_key_material(inputs)
    warnings.extend(admin_plan.warnings)

    regenerate, regenerate_reason, adopt_device_key, keypair_warnings = _plan_node_keypair(inputs)
    warnings.extend(keypair_warnings)

    key_plan = KeyPlan(
        regenerate=regenerate,
        regenerate_reason=regenerate_reason,
        adopt_device_key=adopt_device_key,
        change_admin_keys=admin_plan.change_admin_keys,
        desired_admin_keys=admin_plan.desired,
        desired_admin_key_refs=admin_plan.desired_refs,
        removed_admin_fingerprints=admin_plan.removed,
        revoked_admin_fingerprints=admin_plan.revoked,
        removed_admin_key_refs=admin_plan.removed_refs,
        rejected_admin_key_refs=admin_plan.rejected_refs,
    )

    lockdown = _evaluate_lockdown(inputs, admin_plan.desired)
    if lockdown.reason == LockdownReason.ALLOW_LOCKDOWN_NOT_SET:
        warnings.append(
            PlanWarning(
                PlanWarningCode.LOCKDOWN_NOT_AUTHORIZED,
                "security.is_managed stays false: pass --allow-lockdown to enable it.",
                section="security",
                field="is_managed",
            )
        )

    security_section = _plan_security_section(inputs, key_plan, lockdown)

    if inputs.state is detect.NodeState.FOREIGN:
        warnings.append(
            PlanWarning(
                PlanWarningCode.FOREIGN_NODE,
                f"{live.node_id.display} was not found in the database and does not look "
                "like a factory-default node; it may belong to someone else.",
            )
        )

    sections = _assemble_sections(
        config_sections, module_sections, bluetooth_section, security_section
    )

    return ChangePlan(
        node_id=live.node_id,
        state=inputs.state,
        is_new=inputs.db_entry is None,
        name_change=name_change,
        sections=sections,
        key_plan=key_plan,
        lockdown=lockdown,
        warnings=tuple(warnings),
        ble_pin_set=bluetooth_section is not None,
        hw_model=live.hw_model,
        firmware_version=live.firmware_version,
        role=template.device.role,
        region=template.lora.region,
        db_entry=inputs.db_entry,
    )
