"""Drift detection and repair for an already-provisioned node.

:func:`diff_record` is the pure half: it compares a live device's
:class:`~meshprovision.provisioning.detect.LiveConfig` against the ODS's
recorded :class:`~meshprovision.db.nodes.NodeRecord` and reports every
mismatch as a :class:`Drift`, doing no I/O. :func:`build_repair_plan` is a
thin, opinionated wrapper over
:func:`meshprovision.provisioning.plan.build_plan`: it fixes the
already-provisioned-node defaults (never renaming, reusing the recorded
BLE PIN, regenerating the key only when compromised) and otherwise
delegates every planning decision to ``plan.py``, per this layer's
purity-boundary rule. :func:`repair_node` drives the whole thing through
:func:`meshprovision.provisioning.apply.apply_plan`, and
:func:`reconcile_record` computes the updated :class:`NodeRecord` a
caller should persist afterwards with
:func:`meshprovision.provisioning.apply.persist_result`.

This module performs no database writes itself -- :func:`repair_node`
only executes the plan against the device; the caller is responsible for
calling :func:`meshprovision.provisioning.apply.persist_result` to
actually update the ODS, exactly as ``mesh provision`` does for a fresh
node.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from meshprovision.crypto import redact
from meshprovision.provisioning import apply, detect
from meshprovision.provisioning.plan import ChangePlan, PlanInputs, ResolvedAdminKey, build_plan

if TYPE_CHECKING:
    from meshprovision.config.template import TemplateConfig
    from meshprovision.crypto.keys import KeyPair
    from meshprovision.db.nodes import NodeRecord
    from meshprovision.nodeid import NodeId
    from meshprovision.provisioning.apply import ApplyOutcome, DeviceSession

__all__ = [
    "Drift",
    "DriftKind",
    "RepairReport",
    "build_repair_plan",
    "diff_record",
    "reconcile_record",
    "repair_node",
]


class DriftKind(StrEnum):
    """The category of one detected mismatch between the ODS and a live device."""

    NAME = "name"
    HARDWARE = "hardware"
    FIRMWARE = "firmware"
    RADIO = "radio"
    ADMIN_KEYS = "admin_keys"
    KEY_MATERIAL = "key_material"
    SECURITY = "security"


@dataclass(frozen=True, slots=True)
class Drift:
    """One detected mismatch between a recorded :class:`NodeRecord` and a live device.

    Attributes:
        kind: The category of this mismatch.
        field: Name of the specific field that drifted.
        recorded: What the ODS says, already rendered for display
            (redacted fingerprints for anything key-related).
        observed: What the device says, rendered the same way.
    """

    kind: DriftKind
    field: str
    recorded: str
    observed: str

    def describe(self) -> str:
        """Render this drift as one operator-facing line.

        Returns:
            For example ``"radio.role: recorded=CLIENT, observed=ROUTER"``.
        """
        return f"{self.kind.value}.{self.field}: recorded={self.recorded}, observed={self.observed}"


@dataclass(frozen=True, slots=True)
class RepairReport:
    """The full outcome of one drift-detect-and-repair pass over a node.

    Attributes:
        node_id: The repaired node's id.
        drifts: Every drift detected before the repair plan was applied.
        plan: The repair-flavoured change plan that was built.
        outcome: The result of executing ``plan`` against the device, or
            ``None`` when the plan was never applied.
        record: The updated :class:`NodeRecord` a caller should persist,
            or ``None`` when nothing should be persisted.
    """

    node_id: NodeId
    drifts: tuple[Drift, ...]
    plan: ChangePlan
    outcome: ApplyOutcome | None = None
    record: NodeRecord | None = None

    @property
    def has_drift(self) -> bool:
        """Whether any drift was detected before repair.

        Returns:
            ``True`` if :attr:`drifts` is non-empty.
        """
        return len(self.drifts) > 0

    @property
    def ok(self) -> bool:
        """Whether the repair (if any was applied) succeeded.

        Returns:
            ``True`` when :attr:`outcome` is ``None`` (nothing was
            applied) or :attr:`~meshprovision.provisioning.apply.ApplyOutcome.ok`.
        """
        return self.outcome is None or self.outcome.ok

    def describe(self) -> tuple[str, ...]:
        """Render every drift, followed by every apply result, as operator-facing lines.

        Returns:
            One line per :class:`Drift` (via :meth:`Drift.describe`),
            followed by one line per apply result (via
            :meth:`~meshprovision.provisioning.apply.ApplyOutcome.describe`)
            when :attr:`outcome` is set.
        """
        lines = [drift.describe() for drift in self.drifts]
        if self.outcome is not None:
            lines.extend(self.outcome.describe())
        return tuple(lines)


def _drift_if_differs(kind: DriftKind, field: str, recorded: str, observed: str) -> Drift | None:
    """Build a :class:`Drift` when two already-rendered values differ.

    An empty ``recorded`` value is never drift -- an unfilled ODS column
    is not a claim about the device's state.

    Args:
        kind: The drift category to use if they differ.
        field: The field name to use if they differ.
        recorded: The ODS's rendered value.
        observed: The device's rendered value.

    Returns:
        The :class:`Drift`, or ``None`` when ``recorded`` is empty or the
        two values match.
    """
    if not recorded or recorded == observed:
        return None
    return Drift(kind=kind, field=field, recorded=recorded, observed=observed)


def diff_record(
    live: detect.LiveConfig,
    record: NodeRecord,
    *,
    admin_key_refs: Mapping[bytes, str] | None = None,
) -> tuple[Drift, ...]:
    """Compare a recorded :class:`NodeRecord` against a live device. Pure -- no I/O.

    A comparison is skipped whenever the recorded value is empty: an
    unfilled ODS column is not a claim about the device, so it is never
    reported as drift.

    Args:
        live: The device's freshly read live configuration.
        record: The ODS's recorded state for this node.
        admin_key_refs: A ``{public_key_bytes: key_ref}`` map (built by
            the caller from
            :meth:`~meshprovision.db.keys.KeyRepository.public_key_map`),
            used to render the device's live admin keys back into
            ``Keys``-sheet references for comparison against
            ``record.authorized_admin_keys``. An unknown live key renders
            as ``"<unknown:<fingerprint>>"``.

    Returns:
        One :class:`Drift` per detected mismatch, in a fixed order: name,
        hardware, firmware, radio (role then region), admin keys, key
        material, then security flags.
    """
    refs = admin_key_refs or {}
    drifts: list[Drift] = []

    short_drift = _drift_if_differs(
        DriftKind.NAME, "short_name", record.short_name, live.short_name
    )
    if short_drift is not None:
        drifts.append(short_drift)
    long_drift = _drift_if_differs(DriftKind.NAME, "long_name", record.long_name, live.long_name)
    if long_drift is not None:
        drifts.append(long_drift)

    hw_drift = _drift_if_differs(DriftKind.HARDWARE, "hw_model", record.hw_model, live.hw_model)
    if hw_drift is not None:
        drifts.append(hw_drift)

    firmware_drift = _drift_if_differs(
        DriftKind.FIRMWARE, "firmware_version", record.firmware_version, live.firmware_version
    )
    if firmware_drift is not None:
        drifts.append(firmware_drift)

    live_role = str(live.value("device", "role") or "")
    role_drift = _drift_if_differs(DriftKind.RADIO, "role", record.role, live_role)
    if role_drift is not None:
        drifts.append(role_drift)

    live_region = str(live.value("lora", "region") or "")
    region_drift = _drift_if_differs(DriftKind.RADIO, "region", record.region, live_region)
    if region_drift is not None:
        drifts.append(region_drift)

    live_admin_refs = tuple(
        sorted(
            refs.get(key, f"<unknown:{redact.fingerprint(key)}>")
            for key in live.security.admin_keys
        )
    )
    recorded_admin_refs = tuple(sorted(record.authorized_admin_keys))
    if recorded_admin_refs and live_admin_refs != recorded_admin_refs:
        drifts.append(
            Drift(
                kind=DriftKind.ADMIN_KEYS,
                field="authorized_admin_keys",
                recorded=";".join(recorded_admin_refs),
                observed=";".join(live_admin_refs),
            )
        )

    if live.security.public_key is not None:
        observed_fp = redact.fingerprint(live.security.public_key)
        # record.public_key_ref names the row, not the material -- the
        # caller resolves it to bytes when it wants a fingerprint to
        # compare; without that resolution we can only compare presence.
        # KEY_MATERIAL drift is reported by the caller when it has both
        # sides resolved to raw bytes (see module docstring); here we
        # only flag the case where the recorded ref is empty but the
        # device has a real key, which is always worth surfacing.
        if not record.public_key_ref:
            drifts.append(
                Drift(
                    kind=DriftKind.KEY_MATERIAL,
                    field="public_key",
                    recorded="<none>",
                    observed=observed_fp,
                )
            )

    # is_managed/admin_channel_enabled have no Nodes-sheet column to compare
    # against directly (see DriftKind.SECURITY docstring); the security
    # safety gate in plan.py is what enforces their target values at
    # plan-build time, so this function has nothing to diff for them.

    return tuple(drifts)


def build_repair_plan(
    live: detect.LiveConfig,
    template: TemplateConfig,
    record: NodeRecord,
    *,
    admin_keys: Sequence[ResolvedAdminKey] = (),
    rejected_admin_keys: frozenset[bytes] = frozenset(),
    db_public_key: bytes | None = None,
    node_key_compromised: bool = False,
    node_key_reason: str = "",
    rename: bool = False,
    allow_lockdown: bool = False,
    force_regenerate_key: bool = False,
) -> ChangePlan:
    """Build a repair-flavoured :class:`~meshprovision.provisioning.plan.ChangePlan`.

    A thin, opinionated wrapper over
    :func:`~meshprovision.provisioning.plan.build_plan`: this function's
    only job is fixing the already-provisioned-node defaults documented
    below. Every other planning decision (admin-key resolution, the
    lockdown safety gate, section diffing) belongs to ``plan.py`` and is
    never duplicated here.

    Args:
        live: The device's freshly read live configuration.
        template: The provisioning template.
        record: The node's existing ODS record.
        admin_keys: Resolved admin public keys to authorize.
        rejected_admin_keys: Public keys that failed the weak-key audit
            and must never be authorized.
        db_public_key: The node's own public key as recorded in the
            ``Keys`` sheet, when known.
        node_key_compromised: Whether the node's own key failed the
            weak-key audit and must be regenerated.
        node_key_reason: Human-readable reason for
            ``node_key_compromised``, for logging.
        rename: Whether this repair run is allowed to rename the device.
            An already-provisioned node is never renamed by a repair run
            unless the caller explicitly opts in here -- the existing ODS
            names win by default (``plan.build_plan`` already does this
            whenever ``desired_short_name``/``desired_long_name`` are
            ``None`` and ``db_entry`` has names).
        allow_lockdown: Whether ``is_managed=true`` may be applied.
        force_regenerate_key: Force key regeneration even when
            ``node_key_compromised`` is ``False``.

    Returns:
        The built :class:`~meshprovision.provisioning.plan.ChangePlan`.
    """
    ble_pin = record.ble_pin.get_secret_value() if record.ble_pin is not None else None
    return build_plan(
        PlanInputs(
            live=live,
            template=template,
            db_entry=record,
            state=detect.NodeState.PROVISIONED,
            desired_short_name=record.short_name if rename else None,
            desired_long_name=record.long_name if rename else None,
            ble_pin=ble_pin,
            admin_keys=tuple(admin_keys),
            rejected_admin_keys=rejected_admin_keys,
            db_public_key=db_public_key,
            node_key_compromised=node_key_compromised,
            node_key_reason=node_key_reason,
            allow_lockdown=allow_lockdown,
            force_regenerate_key=force_regenerate_key,
        )
    )


def reconcile_record(record: NodeRecord, live: detect.LiveConfig, plan: ChangePlan) -> NodeRecord:
    """Compute the post-repair :class:`NodeRecord` a caller should persist. Pure.

    Never touches ``ble_pin`` or the timestamp fields -- those are the
    caller's job via
    :meth:`~meshprovision.db.nodes.NodeRepository.upsert`'s own touch
    logic.

    Args:
        record: The node's existing ODS record.
        live: The device's freshly read live configuration (from before
            the repair plan was applied -- name truncation and other
            device-side transformations are re-verified by
            :func:`~meshprovision.provisioning.apply.verify_plan`, not
            re-derived here).
        plan: The repair plan that was built (and, by the time this is
            called, applied).

    Returns:
        A new :class:`NodeRecord` with names, hardware, firmware, role,
        region, and authorized admin keys reconciled from ``plan`` and
        ``live``.
    """
    short_name = plan.name_change.desired_short_name or record.short_name
    long_name = plan.name_change.desired_long_name or record.long_name
    live_role = live.value("device", "role")
    live_region = live.value("lora", "region")
    return record.with_updates(
        short_name=short_name,
        long_name=long_name,
        hw_model=live.hw_model or record.hw_model,
        firmware_version=live.firmware_version or record.firmware_version,
        role=str(live_role) if live_role else record.role,
        region=str(live_region) if live_region else record.region,
        authorized_admin_keys=plan.key_plan.desired_admin_key_refs,
    )


def repair_node(
    session: DeviceSession,
    plan: ChangePlan,
    *,
    keypair: KeyPair | None = None,
    dry_run: bool = False,
    drifts: Sequence[Drift] = (),
) -> RepairReport:
    """Apply a repair plan against a live device and report the outcome.

    Performs no database writes: the caller uses
    :func:`~meshprovision.provisioning.apply.persist_result` (typically
    together with :func:`reconcile_record`) to actually update the ODS.

    Args:
        session: The device session to apply the plan through.
        plan: The repair plan, typically built by :func:`build_repair_plan`.
        keypair: The freshly generated keypair, when
            ``plan.key_plan.regenerate`` is set.
        dry_run: When ``True``, no device writes are attempted.
        drifts: The drifts detected before this repair, for the report.

    Returns:
        The :class:`RepairReport`, with :attr:`RepairReport.outcome` and
        :attr:`RepairReport.record` set from
        :func:`~meshprovision.provisioning.apply.apply_plan`.
    """
    outcome = apply.apply_plan(plan, session, keypair=keypair, dry_run=dry_run)
    return RepairReport(
        node_id=plan.node_id,
        drifts=tuple(drifts),
        plan=plan,
        outcome=outcome,
        record=outcome.record,
    )
