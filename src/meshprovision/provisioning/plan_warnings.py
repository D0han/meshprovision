"""The non-fatal finding type shared by the plan modules.

Its own module so that :mod:`meshprovision.provisioning.plan` and
:mod:`meshprovision.provisioning.plan_admin_keys` can both construct one
without importing each other -- ``plan.py`` imports ``plan_admin_keys``,
so the reverse edge would be a cycle. Deliberately dependency-free: this
module imports nothing but :mod:`dataclasses`.

Re-exported from :mod:`meshprovision.provisioning.plan`, which remains
the documented import site for it.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["PlanWarning"]


@dataclass(frozen=True, slots=True)
class PlanWarning:
    """A non-fatal finding surfaced while building a :class:`ChangePlan`.

    Attributes:
        code: Machine-readable code. One of ``"lockdown_not_authorized"``,
            ``"module_has_no_enabled_field"``, ``"unknown_module"``,
            ``"device_key_differs_from_db"``, ``"foreign_node"``,
            ``"live_admin_key_rejected"``,
            ``"resolved_admin_key_rejected"``,
            ``"resolved_admin_key_forced"``,
            ``"region_change_reboots"``, or ``"name_truncation_risk"``.
        message: Human-readable description of the finding.
        section: Name of the associated config/module-config section,
            when known.
        field: Name of the associated field, when known.
    """

    code: str
    message: str
    section: str | None = None
    field: str | None = None
