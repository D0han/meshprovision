"""The non-fatal finding type shared by the plan modules.

Its own module so that :mod:`meshprovision.provisioning.plan` and
:mod:`meshprovision.provisioning.plan_admin_keys` can both construct one
without importing each other -- ``plan.py`` imports ``plan_admin_keys``,
so the reverse edge would be a cycle. Deliberately dependency-free: this
module imports nothing but :mod:`dataclasses` and :mod:`enum`.

Re-exported from :mod:`meshprovision.provisioning.plan`, which remains
the documented import site for it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

__all__ = ["PlanWarning", "PlanWarningCode"]


class PlanWarningCode(StrEnum):
    """Machine-readable :attr:`PlanWarning.code` values.

    A closed, enumerated vocabulary -- the same StrEnum-over-bare-str
    precedent applied elsewhere in this project (:class:`~meshprovision
    .db.verify.DbProblemKind`, :class:`~meshprovision.crypto.weakkeys
    .WeakKeyCheck`, :class:`~meshprovision.provisioning.plan_render
    .PlanLineKind`). ``PlanWarning.code`` was the one holdout still using
    a bare ``str`` with the allowed values merely listed in prose --
    which is exactly how one real code (``live_admin_key_revoked``) went
    undocumented for a time despite being constructed in production.
    """

    NAME_TRUNCATION_RISK = "name_truncation_risk"
    REGION_CHANGE_REBOOTS = "region_change_reboots"
    UNKNOWN_MODULE = "unknown_module"
    MODULE_HAS_NO_ENABLED_FIELD = "module_has_no_enabled_field"
    DEVICE_KEY_DIFFERS_FROM_DB = "device_key_differs_from_db"
    LOCKDOWN_NOT_AUTHORIZED = "lockdown_not_authorized"
    FOREIGN_NODE = "foreign_node"
    RESOLVED_ADMIN_KEY_FORCED = "resolved_admin_key_forced"
    RESOLVED_ADMIN_KEY_REJECTED = "resolved_admin_key_rejected"
    LIVE_ADMIN_KEY_REVOKED = "live_admin_key_revoked"
    LIVE_ADMIN_KEY_REJECTED = "live_admin_key_rejected"


@dataclass(frozen=True, slots=True)
class PlanWarning:
    """A non-fatal finding surfaced while building a :class:`ChangePlan`.

    Attributes:
        code: Machine-readable code, see :class:`PlanWarningCode`.
        message: Human-readable description of the finding.
        section: Name of the associated config/module-config section,
            when known.
        field: Name of the associated field, when known.
    """

    code: PlanWarningCode
    message: str
    section: str | None = None
    field: str | None = None

    def to_json_dict(self) -> dict[str, object]:
        """Render this warning as a JSON-safe dict.

        Returns:
            A mapping covering every field.
        """
        return {
            "code": self.code,
            "message": self.message,
            "section": self.section,
            "field": self.field,
        }
