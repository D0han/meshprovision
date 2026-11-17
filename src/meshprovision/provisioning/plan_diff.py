"""Diffing desired field values against current ones: :func:`diff_fields` and its comparison.

Split out of :mod:`meshprovision.provisioning.plan_types`, which holds the plan's data types;
:mod:`meshprovision.provisioning.plan` re-exports both names. Same purity invariant as
``plan.py``: zero I/O, zero device access, zero ``datetime.now()``, zero logging side
effects, and it imports nothing from ``meshtastic``, ``httpx``, ``pathlib``, ``odfpy``, or
:mod:`meshprovision.crypto`.
"""

from __future__ import annotations

import math
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from meshprovision.provisioning import detect
from meshprovision.provisioning.plan_types import FieldChange

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

__all__ = ["diff_fields", "values_equal"]


def values_equal(current: object, desired: object) -> bool:
    """Compare a live value against a desired value with type-tolerant semantics.

    Args:
        current: The value read from the live device.
        desired: The value the template wants.

    Returns:
        ``True`` when the two should be treated as equal. A ``bool`` on
        either side requires the other side to also be a ``bool`` (this
        guards against ``True == 1``); two ``int`` values compare exactly
        (a uint32 interval or a bit-flag mask differing in its lowest
        digits is a real change); a ``float`` on either side (with both
        sides otherwise numeric) uses ``math.isclose`` with
        ``rel_tol=1e-6``/``abs_tol=1e-9``; everything else uses plain
        ``==``. ``rel_tol`` is set to float32 precision (with a wide
        margin), not float64: every template float field maps to a
        protobuf ``TYPE_FLOAT`` (32-bit) wire field, so a device's
        read-back is only ever float32-accurate (~1.19e-7 relative error)
        even when the template's own value is an exact Python float.
    """
    current_is_bool = isinstance(current, bool)
    desired_is_bool = isinstance(desired, bool)
    if current_is_bool or desired_is_bool:
        if current_is_bool != desired_is_bool:
            return False
        return current == desired
    if isinstance(current, int) and isinstance(desired, int):
        return current == desired
    if isinstance(current, int | float) and isinstance(desired, int | float):
        return math.isclose(float(current), float(desired), rel_tol=1e-6, abs_tol=1e-9)
    return current == desired


_NO_ADJUSTMENTS: Final[Mapping[tuple[str, str], object]] = MappingProxyType({})


def diff_fields(
    section: str,
    desired: Mapping[str, object],
    current: Callable[[str], object],
    adjusted: Mapping[tuple[str, str], object] = _NO_ADJUSTMENTS,
) -> tuple[FieldChange, ...]:
    """Diff desired field values against current ones, one section.

    Args:
        section: The section name.
        desired: ``{field: value}`` in the order to report.
        current: Returns a field's current value.
        adjusted: ``{(section, field): value}`` the firmware holds in place of the
            desired value (see
            :func:`~meshprovision.provisioning.plan_firmware.firmware_adjustments`).

    Returns:
        One :class:`FieldChange` per field whose current value is neither the desired
        value nor the firmware's adjusted one, in ``desired`` order, carrying the adjusted
        value as :attr:`~FieldChange.firmware_value` and marked secret for a
        :data:`~meshprovision.provisioning.detect.SECRET_FIELDS` pair.
    """
    changes: list[FieldChange] = []
    for field_name, desired_value in desired.items():
        current_value = current(field_name)
        firmware_value = adjusted.get((section, field_name))
        if values_equal(current_value, desired_value) or (
            firmware_value is not None and values_equal(current_value, firmware_value)
        ):
            continue
        changes.append(
            FieldChange(
                section=section,
                field=field_name,
                current=current_value,
                desired=desired_value,
                secret=(section, field_name) in detect.SECRET_FIELDS,
                firmware_value=firmware_value,
            )
        )
    return tuple(changes)
