"""A diff of a template's desired section values against values observed from a node.

A section or field that was not read is "not read", never a change (OPINION-REMOTE-ADMIN
Q4 and the project's hazard A: a partial read must not look like a drift). Callers pass
plain mappings, so this module never sees a ``LiveConfig``, a device or ``build_plan``. The
private key is never compared (COMPARE section 2.1). Pure: nothing here talks to a device.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from meshprovision.provisioning.plan_diff import diff_fields
from meshprovision.provisioning.plan_types import FieldChange

__all__ = ["SectionDiff", "SectionState", "diff_sections"]

_NO_ADJUSTMENTS: Final[Mapping[tuple[str, str], object]] = MappingProxyType({})


class SectionState(StrEnum):
    """What a diff knows about one section.

    Attributes:
        MATCHES: Read, and every desired field was read and matches.
        DIFFERS: Read, and at least one desired field differs.
        NOT_READ: Not read, or read without some desired field and nothing differs.
    """

    MATCHES = "matches"
    DIFFERS = "differs"
    NOT_READ = "not_read"


@dataclass(frozen=True, slots=True)
class SectionDiff:
    """One section's diff.

    Attributes:
        section: The section name.
        state: What is known about it.
        changes: The fields that differ (empty unless :attr:`state` is DIFFERS).
        unread_fields: Desired fields the read section did not carry, in desired order.
            Nothing reads it yet: groundwork for the live read, which
            ``mesh remote diff`` does not have (only ``--dry-run``).
    """

    section: str
    state: SectionState
    changes: tuple[FieldChange, ...] = ()
    unread_fields: tuple[str, ...] = ()


def _diff_section(
    section: str,
    fields: Mapping[str, object],
    read: Mapping[str, object],
    adjusted: Mapping[tuple[str, str], object],
) -> SectionDiff:
    """Diff the desired fields of one section that was read."""
    present = {name: value for name, value in fields.items() if name in read}
    unread = tuple(name for name in fields if name not in read)
    changes = diff_fields(section, present, read.__getitem__, adjusted)
    if changes:
        return SectionDiff(section, SectionState.DIFFERS, changes, unread)
    state = SectionState.NOT_READ if unread else SectionState.MATCHES
    return SectionDiff(section, state, (), unread)


def diff_sections(
    desired: Mapping[str, Mapping[str, object]],
    observed: Mapping[str, Mapping[str, object]],
    *,
    adjusted: Mapping[tuple[str, str], object] = _NO_ADJUSTMENTS,
) -> tuple[SectionDiff, ...]:
    """Diff desired section values against the sections that were read. Pure.

    Args:
        desired: ``{section: {field: value}}`` in the order to report.
        observed: The sections that were read, ``{section: {field: value}}``; a section
            read without some field leaves that field out.
        adjusted: ``{(section, field): value}`` the firmware holds in place of the desired
            value; a read value equal to it counts as matching.

    Returns:
        One :class:`SectionDiff` per desired section, in ``desired`` order. Sections only
        in ``observed`` are not reported.

    Raises:
        ValueError: If ``desired`` holds ``security.private_key``.
    """
    if "private_key" in desired.get("security", {}):
        raise ValueError("the private key is never compared")
    return tuple(
        _diff_section(section, fields, observed[section], adjusted)
        if section in observed
        else SectionDiff(section, SectionState.NOT_READ)
        for section, fields in desired.items()
    )
