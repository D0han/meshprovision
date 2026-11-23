"""The battery level Meshtastic reports for a node on external power.

A leaf module: every renderer and rule that reads a battery level shares
this one sentinel and comparison, so none treats a level above 101 (a
garbled reading near the sentinel) differently from the others.
"""

from __future__ import annotations

from typing import Final

__all__ = ["EXTERNAL_POWER_BATTERY_LEVEL", "is_external_power"]

EXTERNAL_POWER_BATTERY_LEVEL: Final[int] = 101
"""The level firmware reports instead of a percentage while on external power."""


def is_external_power(level: int | None) -> bool:
    """Tell whether a battery level means external power (101, or anything above).

    Args:
        level: The reported battery level, or ``None`` when there is none.

    Returns:
        ``True`` for :data:`EXTERNAL_POWER_BATTERY_LEVEL` or more.
    """
    return level is not None and level >= EXTERNAL_POWER_BATTERY_LEVEL
