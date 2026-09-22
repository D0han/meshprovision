"""Drift detection for an already-provisioned node. Pure -- no I/O.

:func:`diff_record` compares a live device's
:class:`~meshprovision.provisioning.detect.LiveConfig` against the ODS's
recorded :class:`~meshprovision.db.nodes.NodeRecord` and reports every
mismatch as a :class:`Drift`.

Repair itself is not a separate code path: ``mesh provision``
(:func:`meshprovision.cli.provision.run_provision`) is the repair command.
It calls :func:`diff_record` to report drift, then builds one
:class:`~meshprovision.provisioning.plan.PlanInputs` and applies it, exactly
as it does for a fresh node -- ``build_plan`` already implements the
already-provisioned defaults (with ``desired_short_name``/``desired_long_name``
left ``None`` the database's names win, and the caller passes the recorded BLE
PIN back in). Name allocation lives in
:func:`meshprovision.provisioning.pipeline.allocate_names` and record reconciliation in
:meth:`meshprovision.provisioning.plan.ChangePlan.to_record`; this module
deliberately does not duplicate either.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from meshprovision.crypto import redact
from meshprovision.provisioning import detect, pipeline

if TYPE_CHECKING:
    from meshprovision.db.nodes import NodeRecord

__all__ = [
    "Drift",
    "DriftKind",
    "diff_record",
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


def _preferred_ref(material: bytes, public_keys: Mapping[str, bytes]) -> str:
    """Render one live admin key as its preferred ``Keys`` sheet ref."""
    refs = pipeline.match_admin_key_refs(material, public_keys)
    return refs[0] if refs else f"<unknown:{redact.fingerprint(material)}>"


def _recorded_material(ref: str, public_keys: Mapping[str, bytes]) -> bytes | str:
    """Resolve one recorded ``authorized_admin_keys`` ref to its raw material.

    Returns a distinguishable string sentinel (never a valid ``bytes``
    value) for a ref that does not resolve at all, so it can never be
    mistaken for a coincidental material match against a live key --
    genuinely dangling refs still register as drift.

    Args:
        ref: One entry of ``record.authorized_admin_keys``.
        public_keys: ``{key_ref: raw public key}``.

    Returns:
        The raw material, or ``f"<unresolved:{ref}>"``.
    """
    material = public_keys.get(ref)
    return material if material is not None else f"<unresolved:{ref}>"


def _material_sort_key(value: bytes | str) -> bytes:
    """Sort key that orders ``bytes``/``str`` values without a type-mix comparison error."""
    return value if isinstance(value, bytes) else value.encode()


def diff_record(
    live: detect.LiveConfig,
    record: NodeRecord,
    *,
    public_keys: Mapping[str, bytes] | None = None,
) -> tuple[Drift, ...]:
    """Compare a recorded :class:`NodeRecord` against a live device. Pure -- no I/O.

    A comparison is skipped whenever the recorded value is empty: an
    unfilled ODS column is not a claim about the device, so it is never
    reported as drift.

    Args:
        live: The device's freshly read live configuration.
        record: The ODS's recorded state for this node.
        public_keys: The ``{key_ref: raw public key}`` map from
            :meth:`~meshprovision.db.keys.KeyRepository.public_key_map`,
            used to render the device's live admin keys back into
            ``Keys``-sheet references for comparison against
            ``record.authorized_admin_keys``. Passed in this direction
            (never inverted to ``{material: ref}``) because one key may
            be filed under several refs. An unknown live key renders as
            ``"<unknown:<fingerprint>>"``.

    Returns:
        One :class:`Drift` per detected mismatch, in a fixed order: name,
        hardware, firmware, radio (role then region), admin keys, key
        material, then security flags.
    """
    known = public_keys or {}
    drifts: list[Drift] = []

    short_drift = _drift_if_differs(
        DriftKind.NAME, "short_name", record.short_name, live.short_name
    )
    if short_drift is not None:
        drifts.append(short_drift)
    long_drift = _drift_if_differs(DriftKind.NAME, "long_name", record.long_name, live.long_name)
    if long_drift is not None:
        drifts.append(long_drift)

    # A blank live.hw_model paired with a non-None hw_model_raw means the
    # device reported a model this build's enum table doesn't recognize --
    # detect.read_live_config's own "cannot evaluate" sentinel, not a
    # genuine observation of "no hardware model." Comparing it against a
    # real recorded value would report phantom drift, and the caller
    # (plan.py's to_record) must not let it erase what is already
    # recorded either -- see that module for the matching guard.
    if not (live.hw_model_raw is not None and not live.hw_model):
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

    # Compare material, not rendered refs: record.authorized_admin_keys is
    # written from whichever ref the template names (plan_admin_keys.py),
    # with no relationship to _preferred_ref's preference ordering, so a
    # key legitimately filed under more than one ref (mesh admin bootstrap
    # --ref LABEL) drifted forever whenever the template happened to name
    # the non-preferred alias. _preferred_ref is still used to *render*
    # the display strings below -- only the equality check changed.
    live_material = tuple(sorted(live.security.admin_keys))
    recorded_material = tuple(
        sorted(
            (_recorded_material(ref, known) for ref in record.authorized_admin_keys),
            key=_material_sort_key,
        )
    )
    if record.authorized_admin_keys and recorded_material != live_material:
        live_admin_refs = tuple(
            sorted(_preferred_ref(key, known) for key in live.security.admin_keys)
        )
        recorded_admin_refs = tuple(sorted(record.authorized_admin_keys))
        drifts.append(
            Drift(
                kind=DriftKind.ADMIN_KEYS,
                field="authorized_admin_keys",
                recorded=";".join(recorded_admin_refs),
                observed=";".join(live_admin_refs),
            )
        )

    # DriftKind.KEY_MATERIAL is never emitted here: record.public_key_ref
    # (db/nodes.py) is `schema.ref_for(node_id, ...)`, derived from node_id,
    # which is a required field -- it can never be empty for a valid
    # NodeRecord, so a check for "recorded ref empty but device has a real
    # key" can never fire.

    # is_managed/admin_channel_enabled have no Nodes-sheet column to compare
    # against directly (see DriftKind.SECURITY docstring); the security
    # safety gate in plan.py is what enforces their target values at
    # plan-build time, so this function has nothing to diff for them.

    return tuple(drifts)
