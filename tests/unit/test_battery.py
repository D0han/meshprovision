"""One external-power sentinel for every battery reader."""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path

import pytest

from meshprovision.battery import EXTERNAL_POWER_BATTERY_LEVEL, is_external_power
from meshprovision.datasources.models import NodeObservation
from meshprovision.network import relays
from meshprovision.nodeid import NodeId

pytestmark = pytest.mark.unit

SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "meshprovision"


@pytest.mark.parametrize(
    ("level", "powered"), [(None, False), (0, False), (100, False), (101, True), (150, True)]
)
def test_is_external_power(level: int | None, powered: bool) -> None:
    assert is_external_power(level) is powered


def test_the_sentinel_is_101_and_relays_shares_it() -> None:
    assert EXTERNAL_POWER_BATTERY_LEVEL == 101
    assert relays.EXTERNAL_POWER_LEVEL is EXTERNAL_POWER_BATTERY_LEVEL


@pytest.mark.parametrize("level", [101, 150])
def test_a_relay_above_100_is_on_external_power_like_everywhere_else(level: int) -> None:
    observation = NodeObservation(
        node_id=NodeId(0xDEADBE01),
        source="loranet",
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        battery_level=level,
    )

    health = relays.device_health(observation)

    assert health.external_power is True
    assert health.battery_level is None


def test_no_module_compares_a_battery_level_with_100_or_101_itself() -> None:
    """A literal 100 or 101 next to a battery name means a second copy of the sentinel."""
    offenders = []
    for path in sorted(SRC_ROOT.rglob("*.py")):
        if path.name == "battery.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Compare):
                continue
            names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
            names |= {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}
            literals = {
                n.value
                for n in ast.walk(node)
                if isinstance(n, ast.Constant) and n.value in (100, 101)
            }
            if literals and any("batt" in name.lower() or name == "level" for name in names):
                offenders.append(f"{path.relative_to(SRC_ROOT)}:{node.lineno}")
    assert offenders == []
