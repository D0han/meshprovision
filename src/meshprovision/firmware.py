"""Meshtastic firmware version parsing.

A leaf module (stdlib only) so that a pure module such as
:mod:`meshprovision.provisioning.plan`, which must never import
:mod:`meshprovision.crypto`, can still gate a field on the connected
device's firmware version. :mod:`meshprovision.crypto.weakkeys`
re-exports :func:`parse_firmware_version` for its CVE-2025-52464 window
checks, so existing imports from there keep working.
"""

from __future__ import annotations

import re
from typing import Final

__all__ = ["parse_firmware_version"]

_FIRMWARE_VERSION_RE: Final[re.Pattern[str]] = re.compile(r"^\s*v?(\d+)\.(\d+)\.(\d+)")


def parse_firmware_version(raw: str) -> tuple[int, int, int] | None:
    """Parse a Meshtastic firmware version string.

    Tolerates a leading ``v`` and a trailing build hash that Meshtastic
    appends (for example ``"2.6.12.9861e82"``).

    Args:
        raw: The raw firmware version string.

    Returns:
        A ``(major, minor, patch)`` tuple, or ``None`` if ``raw`` does not
        start with a recognizable ``[v]X.Y.Z`` prefix.
    """
    match = _FIRMWARE_VERSION_RE.match(raw)
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
