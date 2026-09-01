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

    live_admin_refs = tuple(sorted(_preferred_ref(key, known) for key in live.security.admin_keys))
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
