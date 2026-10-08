"""Pure change-plan computation: ``(live_config, template, db_entry) -> ChangePlan``.

This module is **strictly pure**: zero I/O, zero device access, zero
``datetime.now()``, zero logging side effects, and it imports nothing
from ``meshtastic``, ``httpx``, ``pathlib``, ``odfpy``, or
:mod:`meshprovision.crypto` itself (transitively, :mod:`~meshprovision.provisioning.detect`
loads only :mod:`meshprovision.crypto.redact`, for ``SecretBytes``; never
``crypto.keys``/``crypto.weakkeys``). :func:`build_plan` turns an already-read
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

from typing import Any, Final

from meshprovision.name_pattern import LONG_NAME_MAX_BYTES, SHORT_NAME_MAX_BYTES
from meshprovision.provisioning import detect
from meshprovision.provisioning.plan_admin_keys import KeyPlan, plan_admin_key_material
from meshprovision.provisioning.plan_security import (
    evaluate_lockdown,
    packet_signature_policy_warning,
    plan_node_keypair,
    plan_security_section,
)
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
    "default_channel",
    "security",
)
"""The config-section write order. ``"security"`` is always last: writing
``is_managed=true`` can lock the node against any further write, so every
other section must land first. Module sections are written after these
(in sorted-name order) but before ``"default_channel"``, which lands
immediately before ``"security"`` -- :func:`build_plan` emits
:attr:`~meshprovision.provisioning.plan_types.ChangePlan.sections` already
in this final execution order, so
:mod:`meshprovision.provisioning.apply` just iterates it. This ordering
invariant is enforced by :func:`~meshprovision.provisioning.apply.apply_plan`,
which stops writing at the first section that fails, so nothing after it
(``security`` or otherwise) is ever sent."""

_REBOOT_LORA_FIELDS: Final[frozenset[str]] = frozenset({"region", "modem_preset"})


def _plan_name_change(inputs: PlanInputs) -> NameChange:
    """Resolve the desired ``short_name``/``long_name``/``is_unmessagable`` (step 1).

    Args:
        inputs: The plan inputs.

    Returns:
        The :class:`NameChange`, computed from
        ``inputs.desired_short_name``/``desired_long_name`` when set,
        else the database entry's name when non-empty, else the live
        name. ``is_unmessagable`` is resolved from ``template.is_unmessagable``
        when set, else the live value (template-only -- no CLI override,
        unlike the names). ``is_licensed`` is always echoed from the live
        value, preserve-only.
    """
    live = inputs.live
    db_entry = inputs.db_entry

    desired_short = inputs.desired_short_name
    if desired_short is None:
        desired_short = db_entry.short_name if db_entry and db_entry.short_name else live.short_name

    desired_long = inputs.desired_long_name
    if desired_long is None:
        desired_long = db_entry.long_name if db_entry and db_entry.long_name else live.long_name

    template_is_unmessagable = inputs.template.is_unmessagable
    desired_is_unmessagable = (
        template_is_unmessagable if template_is_unmessagable is not None else live.is_unmessagable
    )

    return NameChange(
        current_short_name=live.short_name,
        desired_short_name=desired_short,
        current_long_name=live.long_name,
        desired_long_name=desired_long,
        current_is_unmessagable=live.is_unmessagable,
        desired_is_unmessagable=desired_is_unmessagable,
        current_is_licensed=live.is_licensed,
        desired_is_licensed=live.is_licensed,
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
    """
    changes: list[FieldChange] = []
    for field_name, desired_value in model.model_dump(exclude_none=True).items():
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
    """Diff the module-option toggles, telemetry, and neighbor_info fields (steps 3-4).

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

    neighbor_info_changes = _diff_section("neighbor_info", template.neighbor_info, live)
    if neighbor_info_changes:
        module_changes["neighbor_info"] = SectionChange(
            section="neighbor_info",
            kind=live.kind_of("neighbor_info"),
            changes=neighbor_info_changes,
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


def _plan_default_channel_section(
    inputs: PlanInputs,
) -> tuple[SectionChange | None, tuple[PlanWarning, ...]]:
    """Diff the primary channel's module settings (position_precision/is_muted).

    Args:
        inputs: The plan inputs.

    Returns:
        ``(None, ())`` when nothing differs; otherwise a
        ``"default_channel"`` :class:`SectionChange` (kind
        :attr:`~meshprovision.provisioning.detect.SectionKind.CHANNEL`)
        plus one warning -- writing this section has not been verified
        against real firmware as reboot-free, so the operator is told
        explicitly. When the template sets default_channel fields but the
        device reports no enabled primary channel (``live.default_channel``
        is ``{}``, see
        :attr:`~meshprovision.provisioning.detect.LiveConfig.default_channel`),
        ``None`` plus one ``primary_channel_unavailable`` warning instead:
        the channel write sends the whole channel, so
        :func:`~meshprovision.provisioning.apply.write_default_channel`
        refuses it, and planning it would stop the run before ``security``.
    """
    live = inputs.live
    template = inputs.template
    desired_fields = template.default_channel.model_dump(exclude_none=True)
    if desired_fields and not live.default_channel:
        return None, (
            PlanWarning(
                PlanWarningCode.PRIMARY_CHANNEL_UNAVAILABLE,
                "default_channel not changed: the device reports no enabled primary "
                "channel (index 0), and a channel write would replace the whole channel. "
                "Enable the primary channel on the device, or remove default_channel from "
                "the template.",
                section="default_channel",
            ),
        )
    changes = [
        FieldChange(
            section="default_channel",
            field=name,
            current=live.default_channel.get(name),
            desired=desired,
        )
        for name, desired in desired_fields.items()
        if not values_equal(live.default_channel.get(name), desired)
    ]
    if not changes:
        return None, ()
    section = SectionChange(
        section="default_channel", kind=detect.SectionKind.CHANNEL, changes=tuple(changes)
    )
    warning = PlanWarning(
        PlanWarningCode.DEFAULT_CHANNEL_REBOOT_UNKNOWN,
        "Writing default_channel (the primary channel's module settings) has not been "
        "verified against real firmware as reboot-free.",
        section="default_channel",
    )
    return section, (warning,)


def _assemble_sections(
    config_sections: tuple[SectionChange, ...],
    module_sections: tuple[SectionChange, ...],
    bluetooth_section: SectionChange | None,
    default_channel_section: SectionChange | None,
    security_section: SectionChange | None,
) -> tuple[SectionChange, ...]:
    """Combine every section into final execution order (step 10).

    Args:
        config_sections: The ``device``/``position``/``power``/``lora``
            sections, already in that order.
        module_sections: The module sections, already sorted by name.
        bluetooth_section: The Bluetooth section, or ``None``.
        default_channel_section: The default-channel section, or ``None``.
        security_section: The security section, or ``None``.

    Returns:
        ``config_sections``, then ``bluetooth_section`` (its
        :data:`SECTION_ORDER` position, right after ``lora``), then
        ``module_sections``, then ``default_channel_section`` (last among
        non-security entries), then ``security_section`` last.
    """
    ordered: list[SectionChange] = list(config_sections)
    if bluetooth_section is not None:
        ordered.append(bluetooth_section)
    ordered.extend(module_sections)
    if default_channel_section is not None:
        ordered.append(default_channel_section)
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
        AdminKeyRotationRefusedError: If this node's key would regenerate
            or be adopted while it backs an authorized admin key -- see
            :func:`plan_node_keypair`.
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

    default_channel_section, default_channel_warnings = _plan_default_channel_section(inputs)
    warnings.extend(default_channel_warnings)

    admin_plan = plan_admin_key_material(inputs)
    warnings.extend(admin_plan.warnings)

    regenerate, regenerate_reason, adopt_device_key, keypair_warnings = plan_node_keypair(inputs)
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

    lockdown = evaluate_lockdown(inputs, admin_plan.desired)
    if lockdown.reason == LockdownReason.ALLOW_LOCKDOWN_NOT_SET:
        warnings.append(
            PlanWarning(
                PlanWarningCode.LOCKDOWN_NOT_AUTHORIZED,
                "security.is_managed stays false: pass --allow-lockdown to enable it.",
                section="security",
                field="is_managed",
            )
        )

    policy_warning = packet_signature_policy_warning(inputs)
    if policy_warning is not None:
        warnings.append(policy_warning)

    security_section = plan_security_section(inputs, key_plan, lockdown)

    if inputs.state is detect.NodeState.FOREIGN:
        warnings.append(
            PlanWarning(
                PlanWarningCode.FOREIGN_NODE,
                f"{live.node_id.display} was not found in the database and does not look "
                "like a factory-default node; it may belong to someone else.",
            )
        )

    sections = _assemble_sections(
        config_sections,
        module_sections,
        bluetooth_section,
        default_channel_section,
        security_section,
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
        hw_model_raw=live.hw_model_raw,
        firmware_version=live.firmware_version,
        role=template.device.role,
        region=template.lora.region,
        db_entry=inputs.db_entry,
    )
