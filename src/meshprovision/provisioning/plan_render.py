"""Presentation for a :class:`~meshprovision.provisioning.plan.ChangePlan`.

The pure half of what ``mesh provision``/``mesh admin bootstrap`` print:
:func:`describe_plan` renders a change plan (and any pre-existing drift)
as an ordered sequence of :class:`PlanLine` values, each tagged with the
severity the CLI layer should route it through (``ctx.info``/``ctx.warn``/
plain change-list output); :func:`plan_to_json_dict` renders the same
information as a JSON-safe dict. Neither function touches a
:class:`~meshprovision.cli.common.CliContext` or prints anything --
``cli/provision.py``'s ``render_plan`` stays the thin dispatcher that
does.

Deliberately a sibling of :mod:`meshprovision.provisioning.plan` rather
than living inside it: that module documents itself as strictly pure
*domain* logic (zero I/O, not even a presentation-string concern), and
these two functions are presentation-string builders layered on top of
it -- the same role :mod:`meshprovision.status.render` plays for
:mod:`meshprovision.status.report`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from meshprovision.provisioning.plan import ChangePlan
    from meshprovision.provisioning.repair import Drift

__all__ = [
    "PlanLine",
    "PlanLineKind",
    "describe_plan",
    "plan_to_json_dict",
]


class PlanLineKind(StrEnum):
    """Which CLI output channel one :class:`PlanLine` should be routed through."""

    INFO = "info"
    WARNING = "warning"
    CHANGE = "change"


@dataclass(frozen=True, slots=True)
class PlanLine:
    """One line of a rendered plan, tagged with how it should be presented.

    Attributes:
        kind: Which output channel this line belongs on.
        text: The already-redaction-safe line text.
    """

    kind: PlanLineKind
    text: str


def describe_plan(change_plan: ChangePlan, *, drifts: Sequence[Drift] = ()) -> tuple[PlanLine, ...]:
    """Render a change plan (and any pre-existing drift) as ordered lines.

    Args:
        change_plan: The plan to render.
        drifts: Drifts detected against the database before the plan was
            built, when the node was already provisioned.

    Returns:
        The plan rendered as :class:`PlanLine` values, in display order.
    """
    lines: list[PlanLine] = []

    if drifts:
        lines.append(PlanLine(PlanLineKind.INFO, "Drift detected:"))
        for drift in drifts:
            lines.append(PlanLine(PlanLineKind.INFO, drift.describe()))

    if change_plan.is_empty:
        lines.append(PlanLine(PlanLineKind.INFO, "No changes needed."))
    else:
        lines.append(PlanLine(PlanLineKind.INFO, "Planned changes:"))
        for change_line in change_plan.describe():
            lines.append(PlanLine(PlanLineKind.CHANGE, change_line))

    for warning in change_plan.warnings:
        lines.append(PlanLine(PlanLineKind.WARNING, warning.message))

    lines.append(PlanLine(PlanLineKind.INFO, change_plan.summary()))

    if change_plan.reboots_device:
        lines.append(PlanLine(PlanLineKind.WARNING, "Applying this plan reboots the device."))

    return tuple(lines)


def plan_to_json_dict(
    change_plan: ChangePlan, *, drifts: Sequence[Drift] = ()
) -> dict[str, object]:
    """Render a change plan (and any pre-existing drift) as a JSON-safe dict.

    Args:
        change_plan: The plan to render.
        drifts: Drifts detected against the database before the plan was
            built, when the node was already provisioned.

    Returns:
        A mapping with ``detection``, ``drifts``, and ``plan`` keys.
    """
    return {
        "detection": {
            "node_id": change_plan.node_id.hex,
            "state": change_plan.state.value,
            "is_new": change_plan.is_new,
        },
        "drifts": [
            {
                "kind": drift.kind.value,
                "field": drift.field,
                "recorded": drift.recorded,
                "observed": drift.observed,
            }
            for drift in drifts
        ],
        "plan": change_plan.to_json_dict(),
    }
