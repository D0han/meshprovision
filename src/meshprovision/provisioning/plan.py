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

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Final

from meshprovision.enums import MODULES_WITHOUT_ENABLED
from meshprovision.firmware import derives_node_id_from_key, parse_firmware_version
from meshprovision.name_pattern import LONG_NAME_MAX_BYTES, SHORT_NAME_MAX_BYTES
from meshprovision.provisioning import detect
from meshprovision.provisioning.plan_admin_keys import KeyPlan, plan_admin_key_material
from meshprovision.provisioning.plan_firmware import (
    custom_modem_refusal,
    firmware_adjustments,
    known_only_warning,
    local_admin_refusal,
    replaced_role_refusal,
    role_change_warning,
)
from meshprovision.provisioning.plan_lora import (
    channel_num_wrap_warning,
    lora_firmware_refusal,
    lora_write_reboots,
    primary_name_slot_warning,
    radio_move_warning,
)
from meshprovision.provisioning.plan_security import (
    evaluate_lockdown,
    packet_signature_policy_warning,
    plan_node_keypair,
    plan_security_section,
    switches_serial_api_off,
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

_SILENCING_LORA_FIELDS: Final[tuple[str, ...]] = ("tx_enabled", "hop_limit")
"""The ``lora`` fields whose template value every ``lora`` section carries (see
:attr:`SectionChange.template_values`): a write must never silence the
radio by sending a value the template did not ask for."""

_NO_ADJUSTMENTS: Final[Mapping[tuple[str, str], object]] = MappingProxyType({})


def _db_name_or_live(db_name: str, live_name: str) -> str:
    """Pick the recorded name, unless it is empty or only the live one stripped.

    The database strips surrounding whitespace from every name, so a
    device named ``"AB "`` is recorded as ``"AB"``; that alone is no
    reason to rename the device.

    Args:
        db_name: The database entry's name, or ``""``.
        live_name: The device's live name.

    Returns:
        ``live_name`` when ``db_name`` is empty or equals it stripped,
        else ``db_name``.
    """
    if not db_name or db_name == live_name.strip():
        return live_name
    return db_name


def _plan_name_change(inputs: PlanInputs, adjusted: Mapping[tuple[str, str], object]) -> NameChange:
    """Resolve the desired ``short_name``/``long_name``/``is_unmessagable`` (step 1).

    Args:
        inputs: The plan inputs.
        adjusted: See :func:`_diff_section`; its ``("owner",
            "is_unmessagable")`` entry is what a role change makes the
            firmware set.

    Returns:
        The :class:`NameChange`, computed from
        ``inputs.desired_short_name``/``desired_long_name`` when set,
        else the database entry's name when non-empty and not just the
        live name stripped of surrounding whitespace, else the live
        name. ``is_unmessagable`` is resolved from ``template.is_unmessagable``
        when set, else the live value (template-only -- no CLI override,
        unlike the names), else the live value when it already is what
        the firmware sets in its place on this run. ``is_licensed`` is
        always echoed from the live value, preserve-only.
    """
    live = inputs.live
    db_entry = inputs.db_entry

    desired_short = inputs.desired_short_name
    if desired_short is None:
        desired_short = _db_name_or_live(db_entry.short_name if db_entry else "", live.short_name)

    desired_long = inputs.desired_long_name
    if desired_long is None:
        desired_long = _db_name_or_live(db_entry.long_name if db_entry else "", live.long_name)

    template_is_unmessagable = inputs.template.is_unmessagable
    firmware_is_unmessagable = adjusted.get(("owner", "is_unmessagable"))
    already_as_firmware_sets = (
        firmware_is_unmessagable is not None and live.is_unmessagable == firmware_is_unmessagable
    )
    desired_is_unmessagable = (
        template_is_unmessagable
        if template_is_unmessagable is not None and not already_as_firmware_sets
        else live.is_unmessagable
    )

    return NameChange(
        current_short_name=live.short_name,
        desired_short_name=desired_short,
        current_long_name=live.long_name,
        desired_long_name=desired_long,
        current_is_unmessagable=live.is_unmessagable,
        desired_is_unmessagable=desired_is_unmessagable,
        desired_is_licensed=live.is_licensed,
        firmware_is_unmessagable=(
            firmware_is_unmessagable if isinstance(firmware_is_unmessagable, bool) else None
        ),
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
    for field, desired, limit in (
        ("short_name", name_change.desired_short_name, SHORT_NAME_MAX_BYTES),
        ("long_name", name_change.desired_long_name, LONG_NAME_MAX_BYTES),
    ):
        size = len(desired.encode("utf-8"))
        if size > limit:
            warnings.append(
                PlanWarning(
                    PlanWarningCode.NAME_TRUNCATION_RISK,
                    f"Desired {field} {desired!r} is {size} UTF-8 bytes, over the "
                    f"{limit}-byte firmware limit, and will be truncated silently.",
                    field=field,
                )
            )
    return tuple(warnings)


def _diff_section(
    section_name: str,
    model: Any,
    live: detect.LiveConfig,
    adjusted: Mapping[tuple[str, str], object] = _NO_ADJUSTMENTS,
) -> tuple[FieldChange, ...]:
    """Diff one template section model against the live device state.

    Args:
        section_name: The section name, used both to read the template
            model's dumped fields and to look up the live value.
        model: The template's pydantic section model (for example
            ``template.device``).
        live: The device's live configuration.
        adjusted: ``{(section, field): value}`` the firmware holds in place
            of the template value (see
            :func:`~meshprovision.provisioning.plan_firmware.firmware_adjustments`).

    Returns:
        One :class:`FieldChange` per field whose live value is neither the
        template value nor the firmware's adjusted one, in the model's own
        field-declaration order, carrying the adjusted value as
        :attr:`~FieldChange.firmware_value`.
    """
    changes: list[FieldChange] = []
    for field_name, desired_value in model.model_dump(exclude_none=True).items():
        current_value = live.value(section_name, field_name)
        firmware_value = adjusted.get((section_name, field_name))
        if values_equal(current_value, desired_value) or (
            firmware_value is not None and values_equal(current_value, firmware_value)
        ):
            continue
        changes.append(
            FieldChange(
                section=section_name,
                field=field_name,
                current=current_value,
                desired=desired_value,
                firmware_value=firmware_value,
            )
        )
    return tuple(changes)


def _plan_config_sections(
    inputs: PlanInputs, adjusted: Mapping[tuple[str, str], object]
) -> tuple[tuple[SectionChange, ...], tuple[PlanWarning, ...]]:
    """Diff the ``device``/``position``/``power``/``lora`` sections (step 2).

    Args:
        inputs: The plan inputs.
        adjusted: See :func:`_diff_section`.

    Returns:
        The non-empty sections, in :data:`SECTION_ORDER` order, plus a
        ``"region_change_reboots"`` warning when a ``lora`` change moves
        the radio (see
        :func:`~meshprovision.provisioning.plan_lora.radio_move_warning`).
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
        changes = _diff_section(section_name, model, live, adjusted)
        if not changes:
            continue
        reboots = section_name == "lora" and lora_write_reboots(inputs, changes)
        moved = radio_move_warning(inputs, changes) if section_name == "lora" else None
        if moved is not None:
            warnings.append(moved)
        template_values = (
            tuple((name, getattr(model, name)) for name in _SILENCING_LORA_FIELDS)
            if section_name == "lora"
            else ()
        )
        sections.append(
            SectionChange(
                section=section_name,
                kind=live.kind_of(section_name),
                changes=changes,
                reboots_device=reboots,
                template_values=template_values,
            )
        )

    return tuple(sections), tuple(warnings)


def _plan_module_sections(
    inputs: PlanInputs, adjusted: Mapping[tuple[str, str], object]
) -> tuple[tuple[SectionChange, ...], tuple[PlanWarning, ...]]:
    """Diff the module-option toggles, telemetry, and neighbor_info fields (steps 3-4).

    Args:
        inputs: The plan inputs.
        adjusted: See :func:`_diff_section`.

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
        if opt in MODULES_WITHOUT_ENABLED:
            # No on/off switch to write; the template warned once at load.
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

    telemetry_changes = _diff_section("telemetry", template.telemetry, live, adjusted)
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
    inputs: PlanInputs, adjusted: Mapping[tuple[str, str], object]
) -> tuple[SectionChange | None, tuple[PlanWarning, ...]]:
    """Diff the primary channel's module settings (position_precision/is_muted).

    Args:
        inputs: The plan inputs.
        adjusted: See :func:`_diff_section`.

    Returns:
        ``(None, ())`` when nothing differs; otherwise a
        ``"default_channel"`` :class:`SectionChange` (kind
        :attr:`~meshprovision.provisioning.detect.SectionKind.CHANNEL`)
        plus one ``default_channel_reboot_unknown`` warning (the code name
        predates the source check): the write applies without a reboot,
        read in the firmware source but not tried on a device. When the
        template sets default_channel fields but the
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
    changes: list[FieldChange] = []
    for name, desired in desired_fields.items():
        current = live.default_channel.get(name)
        firmware_value = adjusted.get(("default_channel", name))
        if values_equal(current, desired) or (
            firmware_value is not None and values_equal(current, firmware_value)
        ):
            continue
        changes.append(
            FieldChange(
                section="default_channel",
                field=name,
                current=current,
                desired=desired,
                firmware_value=firmware_value,
            )
        )
    if not changes:
        return None, ()
    section = SectionChange(
        section="default_channel", kind=detect.SectionKind.CHANNEL, changes=tuple(changes)
    )
    warning = PlanWarning(
        PlanWarningCode.DEFAULT_CHANNEL_REBOOT_UNKNOWN,
        "Writing default_channel (the primary channel's module settings) applies without "
        "a reboot (read in the firmware source at 2.7.26 and 2.8.3; not tried on a device).",
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


def _peers_keep_old_key_warning(node: str) -> PlanWarning:
    """Warn that a new key on firmware older than 2.8 leaves other nodes with the old one.

    Such firmware keeps the node id, and a node that already holds a
    public key for an id never replaces it from a NodeInfo
    (``NodeDB::updateUser``, "not updating"): its direct messages and
    remote admin to the node fail (``NO_CHANNEL``, seen in the firmware
    simulator at 2.6.13 and 2.7.26). The remedy named, removing the node
    there (``removeNodeByNum``) and adding it back with ``mesh peers``,
    is read in the source only, not yet tried on a device or in the
    simulator. ``mesh peers`` reports such a node and leaves it alone.

    Args:
        node: The node's display id.

    Returns:
        A ``peers_keep_old_key`` warning.
    """
    return PlanWarning(
        PlanWarningCode.PEERS_KEEP_OLD_KEY,
        f"Applying this plan gives {node} a new key under the same node id (firmware < 2.8 "
        "keeps the id). Other nodes that already hold its old key keep it, so their direct "
        f"messages and remote admin to {node} fail. The expected remedy (untested): run "
        f"`meshtastic --remove-node '{node}'` on each, then `mesh peers` there.",
        section="security",
        field="public_key",
    )


def build_plan(inputs: PlanInputs) -> ChangePlan:
    """Build an exact, deterministic :class:`ChangePlan` from resolved inputs.

    Pure: no I/O, no device access, no clock reads. See the module
    docstring for the full purity contract and the admin-key rule.
    ``inputs.live`` must be a complete local read from
    :func:`~meshprovision.provisioning.detect.read_live_config`, never a
    backup, partial or remote view: the key decisions trust that every
    security field was read (``tests/unit/test_import_contracts.py``
    keeps the callers to ``mesh provision``'s pipeline).

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
        DetectionError: If the device reported no key material at all
            although the database holds its key and its region is set --
            see :func:`plan_node_keypair`.
        LockdownRefusedError: If the template opts into
            ``security.is_managed`` but the safety gates are not
            satisfied (zero admin keys, no private counterpart on hand,
            or a key fails the weak-key audit).
        PlanConflictError: If the plan would write role ``REPEATER`` to
            firmware that replaces it (see
            :func:`~meshprovision.provisioning.plan_firmware.replaced_role_refusal`),
            ``rebroadcast_mode`` ``KNOWN_ONLY`` to firmware that then
            ignores the connected client (see
            :func:`~meshprovision.provisioning.plan_firmware.local_admin_refusal`),
            ``lora.use_preset`` false to a node holding a radio
            parameter of 0 (see
            :func:`~meshprovision.provisioning.plan_firmware.custom_modem_refusal`),
            or a region or preset the device's firmware cannot run (see
            :func:`~meshprovision.provisioning.plan_lora.lora_firmware_refusal`).
    """
    live = inputs.live
    template = inputs.template
    warnings: list[PlanWarning] = []

    adjustments = firmware_adjustments(inputs)
    adjusted = {(a.section, a.field): a.value for a in adjustments}

    name_change = _plan_name_change(inputs, adjusted)
    warnings.extend(_name_warnings(name_change))

    config_sections, config_warnings = _plan_config_sections(inputs, adjusted)
    warnings.extend(config_warnings)
    writes_device = any(s.section == "device" for s in config_sections)
    writes_lora = any(s.section == "lora" for s in config_sections)
    for refusal in (
        replaced_role_refusal(inputs, writes_device=writes_device),
        local_admin_refusal(inputs, writes_device=writes_device),
        custom_modem_refusal(inputs, writes_lora=writes_lora),
        lora_firmware_refusal(inputs, writes_lora=writes_lora),
    ):
        if refusal is not None:
            raise refusal

    module_sections, module_warnings = _plan_module_sections(inputs, adjusted)
    warnings.extend(module_warnings)
    warnings.extend(a.warning for a in adjustments if a.warning is not None)
    warnings.extend(
        w
        for w in (
            role_change_warning(inputs),
            known_only_warning(inputs),
            channel_num_wrap_warning(inputs),
            primary_name_slot_warning(inputs),
        )
        if w is not None
    )

    bluetooth_section = _plan_bluetooth_section(inputs)

    default_channel_section, default_channel_warnings = _plan_default_channel_section(
        inputs, adjusted
    )
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

    if regenerate and derives_node_id_from_key(live.firmware_version):
        warnings.append(
            PlanWarning(
                PlanWarningCode.NODE_ID_CHANGES,
                f"Applying this plan changes the node id of {live.node_id.display}: firmware "
                ">= 2.8 derives it from the new key. The database follows it to the new id.",
                section="security",
                field="public_key",
            )
        )
    elif regenerate and parse_firmware_version(live.firmware_version) is not None:
        warnings.append(_peers_keep_old_key_warning(live.node_id.display))

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
    if security_section is not None and switches_serial_api_off(security_section):
        warnings.append(
            PlanWarning(
                PlanWarningCode.SERIAL_API_DISABLED,
                "security.serial_enabled false switches off the serial (USB) API: from the "
                "commit on, the node answers only over BLE or TCP, where enabled.",
                section="security",
                field="serial_enabled",
            )
        )

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
