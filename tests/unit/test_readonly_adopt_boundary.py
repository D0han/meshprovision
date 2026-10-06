"""The read-only guard: `mesh adopt` structurally cannot write the device."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.unit.conftest import source_without_docstring

pytestmark = pytest.mark.unit

SRC = Path(__file__).resolve().parents[2] / "src" / "meshprovision"

# cli/adopt.py bans the *names* outright (its module docstring, lines 3-4).
# Beyond this module's own write path, the list also names other known
# mutating meshtastic MeshInterface/Node methods, so a future change that
# called one of them directly on the connected iface (bypassing apply_plan
# entirely) still trips this guard -- not just the write-verification
# machinery this module was originally written to avoid.
_CLI_ADOPT_FORBIDDEN = frozenset(
    {
        "apply_plan",
        "ReconnectingSession",
        "InPlaceSession",
        "device_session",
        "writeConfig",
        "setOwner",
        "setFixedPosition",
        "removeFixedPosition",
        "reboot",
        "shutdown",
        "resetNodeDb",
        "sendText",
        "sendPosition",
        "sendWaypoint",
        "commitConfig",
        "factoryReset",
        "exitSimulator",
    }
)


def test_cli_adopt_never_names_a_device_write_symbol() -> None:
    code = source_without_docstring(SRC / "cli" / "adopt.py")
    found = sorted(name for name in _CLI_ADOPT_FORBIDDEN if name in code)
    assert found == [], f"cli/adopt.py must not reference: {found}"
