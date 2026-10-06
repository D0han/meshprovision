"""The read-only guard: `mesh template validate` structurally cannot touch a database or device."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.unit.conftest import source_without_docstring

pytestmark = pytest.mark.unit

SRC = Path(__file__).resolve().parents[2] / "src" / "meshprovision"

# cli/template_cmd.py bans the *names* outright (its module docstring
# already explains why: template validation must work with no database
# or device involved at all, unlike mesh db verify's degraded-not-absent
# template cross-check).
_CLI_TEMPLATE_FORBIDDEN = frozenset(
    {
        "OdsDatabase",
        "NodeRepository",
        "KeyRepository",
        "atomic_writer",
        "open_database",
        "apply_plan",
        "ReconnectingSession",
        "InPlaceSession",
        "device_session",
        "writeConfig",
    }
)


def test_cli_template_never_names_a_db_or_device_write_symbol() -> None:
    code = source_without_docstring(SRC / "cli" / "template_cmd.py")
    found = sorted(name for name in _CLI_TEMPLATE_FORBIDDEN if name in code)
    assert found == [], f"cli/template_cmd.py must not reference: {found}"
