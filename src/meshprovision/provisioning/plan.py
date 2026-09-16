"""Pure change-plan computation: ``(live_config, template, db_entry) -> ChangePlan``.

This module is **strictly pure**: zero I/O, zero device access, zero
``datetime.now()``, zero logging side effects, and it imports nothing
from ``meshtastic``, ``httpx``, ``pathlib``, ``odfpy``, or
:mod:`meshprovision.crypto`. :func:`build_plan` turns an already-read
:class:`~meshprovision.provisioning.detect.LiveConfig`, an already-loaded
:class:`~meshprovision.config.template.TemplateConfig`, an optional
:class:`~meshprovision.db.nodes.NodeRecord`, and pre-resolved admin keys
into an exact, deterministic, orderable
:class:`~meshprovision.provisioning.plan_types.ChangePlan` --
:mod:`meshprovision.provisioning.apply` executes it field-for-field, and
``mesh provision --dry-run`` prints it verbatim. Purity is what makes
``--dry-run`` an *exact* preview rather than an approximation, and it is
where the bulk of this project's unit-test coverage lands.

Given identical inputs, :func:`build_plan` produces byte-identical
``ChangePlan.to_json_dict`` output: no iteration over an unsorted
``set``, no reliance on ``dict`` insertion order beyond the fixed
:data:`SECTION_ORDER`, and no input is ever mutated (every input is
already frozen; this module never calls ``.append`` on one).

**The types this module builds** (``ChangePlan``, ``PlanInputs``,
``FieldChange``, ``SectionChange``, ``NameChange``,
``LockdownDecision``/``LockdownReason``, ``values_equal``) live in
:mod:`meshprovision.provisioning.plan_types` -- this module imports and
re-exports every one of them via ``__all__`` unchanged, so a caller may
still import any of them from here. The split exists so this file holds
only the ``_plan_*``/:func:`build_plan` decision logic, mirroring the
project's other single-responsibility extractions out of what was
originally one much larger module (see
:mod:`meshprovision.provisioning.plan_admin_keys`/
:mod:`meshprovision.provisioning.plan_render`/
:mod:`meshprovision.provisioning.plan_warnings`).

**The admin-key rule** lives with the code that implements it, in
:mod:`meshprovision.provisioning.plan_admin_keys` -- see that module's docstring
for the exact rule :func:`build_plan` applies to ``template.admin_nodes``,
``security.admin_key``, and ``--allow-weak-admin-key``.

Secret hygiene: this module never imports :mod:`meshprovision.crypto`
(digests are the caller's job), yet it still never lets raw key bytes
reach a ``repr()``: :class:`~meshprovision.provisioning.plan_admin_keys.ResolvedAdminKey`
reuses its own caller-supplied ``fingerprint`` field, and
:class:`~meshprovision.provisioning.plan_admin_keys.KeyPlan` and
:class:`~meshprovision.provisioning.plan_types.FieldChange` render a fixed
``<redacted>`` placeholder for any secret material in their custom
``__repr__``/``describe``/``to_json_dict``. Dropped live admin keys are
named only as positional labels (``"live-admin[0]"``, ...), never
fingerprinted, since computing a digest would require :mod:`hashlib` --
``apply.py``/the render layer resolve a real fingerprint for those,
downstream of this module.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Final

from meshprovision.config.template import LONG_NAME_MAX_BYTES, SHORT_NAME_MAX_BYTES
from meshprovision.errors import LockdownRefusedError
from meshprovision.provisioning import detect
from meshprovision.provisioning.plan_admin_keys import KeyPlan, _plan_admin_key_material
from meshprovision.provisioning.plan_types import (
    ChangePlan,
    FieldChange,
    LockdownDecision,
    LockdownReason,
    NameChange,
    PlanInputs,
    SectionChange,
    values_equal,
)
from meshprovision.provisioning.plan_warnings import PlanWarning, PlanWarningCode

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
emits :attr:`~meshprovision.provisioning.plan_types.ChangePlan.sections`
already in this final execution order, so
:mod:`meshprovision.provisioning.apply` just iterates it."""

_POSITION_FIXED_FIELDS: Final[frozenset[str]] = frozenset(
    {"fixed_latitude", "fixed_longitude", "fixed_altitude"}
)

_REBOOT_LORA_FIELDS: Final[frozenset[str]] = frozenset({"region", "modem_preset"})


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
        that is present in :attr:`~meshprovision.provisioning.plan_types.ChangePlan.sections`.
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
