"""The remote diff dry run's text report and ``--json`` document, against literal goldens."""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import pytest

from meshprovision.remote.ledger import diff_ledger
from meshprovision.remote.plan import (
    plan_dry_run,
)
from meshprovision.remote.plan_types import (
    AirUtilReading,
    Destination,
    DryRunInputs,
    DryRunPlan,
    Gateway,
)
from meshprovision.remote.render import ESTIMATE_LINE, plan_to_json, render_text

pytestmark = pytest.mark.unit

KEY = bytes(range(32))

EXAMPLE_SECTIONS = frozenset(
    {
        "owner",
        "device",
        "position",
        "power",
        "lora",
        "default_channel",
        "security",
        "telemetry",
        "neighbor_info",
        "mqtt",
        "serial",
        "range_test",
        "store_forward",
        "remote_hardware",
        "paxcounter",
    }
)

G1_BLOCK = [
    "Requests (2, --section):",
    "  metadata                91 B measured",
    "  lora                    89 B measured",
    "Radio: EU_868 LONG_FAST, slot 44 ms (4 CAD symbols assumed), settle 25-120 s",
    "Deadline per request, and the longest run if every request ran to it (CW 7 / CW 8):",
    "  1 link: 7.4 s / 7.4 s, run 135 s / 135 s",
    "  2 links: 22.9 s / 34.1 s, run 166 s / 188 s",
    "  3 links: 38.4 s / 60.9 s, run 197 s / 242 s",
    "  4 links: 53.8 s / 87.6 s, run 228 s / 295 s",
    "Airtime in one rolling hour, CW 7 / CW 8 (spurious retransmits x1.000 / x1.471):",
    "  gateway      1.28 s / 1.89 s (3.85 s if no request is answered)",
    "  each relay   3.14 s / 4.61 s (5.60 s / 8.23 s at the largest replies)",
    "  destination  1.86 s / 2.73 s",
    "  polite share 36.00 s per relay: fits 11 times per rolling hour at CW 7; "
    "fits 7 times per rolling hour at CW 8",
]

G2_AIRTIME = [
    "Airtime in one rolling hour, CW 7 / CW 8 (spurious retransmits x1.000 / x1.471):",
    "  gateway      9.62 s / 14.14 s (48.08 s if no request is answered)",
    "  each relay   30.99 s / 45.57 s (41.96 s / 61.72 s at the largest replies)",
    "  destination  21.37 s / 31.43 s",
    "  polite share 36.00 s per relay: fits 1 time per rolling hour at CW 7; does not fit at CW 8",
]

G6_LINES = [
    "Radio: EU_868 LONG_MODERATE, slot 81 ms (4 CAD symbols assumed), settle 45-120 s",
    "Airtime in one rolling hour, CW 7 / CW 8 (spurious retransmits x1.324 / x1.662):",
    "  gateway      5.39 s / 6.77 s (20.36 s if no request is answered)",
    "  each relay   13.73 s / 17.24 s (26.40 s / 33.14 s at the largest replies)",
    "  destination  8.34 s / 10.47 s",
    "  polite share 36.00 s per relay: fits 2 times per rolling hour at CW 7; "
    "fits 2 times per rolling hour at CW 8",
]


def _plan(**overrides: Any) -> DryRunPlan:
    """G1 by default: LONG_FAST, ``--section lora``, destination 2.8.3, gateway 2.7.26."""
    fields: dict[str, Any] = {
        "destination": Destination(
            "!deadbe01",
            True,
            template_managed=True,
            firmware="2.8.3",
            authorized_keys=frozenset({KEY}),
        ),
        "gateway": Gateway("!deadbe0a", True, firmware="2.7.26", public_key=KEY),
        "region": "EU_868",
        "preset": "LONG_FAST",
        "hop_limit": 3,
        "override_duty_cycle": False,
        "template_sections": EXAMPLE_SECTIONS,
        "requested_sections": frozenset({"lora"}),
        **overrides,
    }
    return plan_dry_run(DryRunInputs(**fields))


def _g2() -> DryRunPlan:
    destination = Destination(
        "!deadbe01",
        True,
        template_managed=True,
        firmware="2.7.11.example",
        authorized_keys=frozenset({KEY}),
    )
    return _plan(destination=destination, gateway=None, requested_sections=frozenset())


def _g3() -> DryRunPlan:
    return _plan(preset="LONG_MODERATE", gateway=None, requested_sections=frozenset())


def _contains_block(lines: list[str], block: list[str]) -> bool:
    return any(lines[i : i + len(block)] == block for i in range(len(lines)))


def _walk(value: object) -> list[object]:
    if isinstance(value, dict):
        return [item for child in value.values() for item in _walk(child)]
    if isinstance(value, list):
        return [item for child in value for item in _walk(child)]
    return [value]


def test_g1_text_block() -> None:
    lines = render_text(_plan()).splitlines()

    assert _contains_block(lines, G1_BLOCK)
    assert lines[0] == (
        "Remote diff dry run for !deadbe01: nothing was sent and no radio was contacted."
    )
    assert lines[1] == ESTIMATE_LINE
    assert (
        "Verdict: allowed offline (every rule this version can check passes; "
        "this version cannot run the read)"
    ) in lines
    assert "Gateway: !deadbe0a, authorized, 3 transmissions per unanswered request" in lines
    assert "Destination: !deadbe01, firmware 2.8.3" in lines


def test_g2_text() -> None:
    text = render_text(_g2())
    lines = text.splitlines()

    assert _contains_block(lines, G2_AIRTIME)
    assert "  remote_hardware        255 B maximum" in lines
    assert "  neighbor_info          255 B maximum" in lines
    assert "Destination: !deadbe01, firmware 2.7.11 (recorded 2.7.11.example)" in lines
    assert "Gateway: not given" in lines
    assert "Notes:" in lines
    assert any(line.startswith("  worst_case_over_share: at contention window 8") for line in lines)
    assert "Refused:" not in lines


def test_g3_text_shows_refusals() -> None:
    lines = render_text(_g3()).splitlines()

    assert "Verdict: refused" in lines
    assert "Refused:" in lines
    assert any(line.startswith("  full_diff_on_slow_preset: ") for line in lines)


def test_g6_airtime_block() -> None:
    plan = _plan(preset="LONG_MODERATE", gateway=None)

    lines = render_text(plan).splitlines()

    assert all(line in lines for line in G6_LINES)


@pytest.mark.parametrize(
    ("recorded", "expected"),
    [
        pytest.param("", "unknown (none recorded)", id="none"),
        pytest.param("x", "unknown (recorded x)", id="unparseable"),
        pytest.param("2.8.3", "2.8.3", id="plain"),
        pytest.param("v2.8.3.abc", "2.8.3 (recorded v2.8.3.abc)", id="decorated"),
    ],
)
def test_firmware_line_variants(recorded: str, expected: str) -> None:
    destination = Destination("!deadbe01", True, template_managed=True, firmware=recorded)

    lines = render_text(_plan(destination=destination)).splitlines()

    assert f"Destination: !deadbe01, firmware {expected}" in lines


def test_no_estimate_line() -> None:
    plan = _plan(region="EU_433")

    lines = render_text(plan).splitlines()

    assert lines[-1] == "No airtime estimate: the region or the preset is outside the model."
    assert not any(line.startswith("Radio:") for line in lines)


def test_budget_none_line() -> None:
    plan = _plan()
    estimate = plan.estimate
    assert estimate is not None
    us = [
        diff_ledger("LONG_FAST", "US", [91, 89], slot_ms=44, cw=cw, gateway_attempts=3)
        for cw in (7, 8)
    ]
    swapped = dataclasses.replace(
        plan, estimate=dataclasses.replace(estimate, ledger=us[0], ledger_worst_case=us[1])
    )

    lines = render_text(swapped).splitlines()

    assert "  polite share none (the region has no duty-cycle limit)" in lines


def test_json_g1() -> None:
    document = plan_to_json(_plan())

    assert list(document) == [
        "dry_run",
        "node",
        "verdict",
        "refusals",
        "notes",
        "full_diff",
        "firmware",
        "gateway",
        "destination_air_util_tx",
        "requests",
        "estimate",
    ]
    assert document["dry_run"] is True
    assert document["node"] == "!deadbe01"
    assert document["verdict"] == "allowed"
    assert document["firmware"] == {"recorded": "2.8.3", "version": "2.8.3", "security_read": False}
    assert document["gateway"] == {
        "node": "!deadbe0a",
        "authorization": "authorized",
        "unanswered_attempts": 3,
    }
    assert document["destination_air_util_tx"] is None
    estimate: Any = document["estimate"]
    assert list(estimate) == [
        "region",
        "preset",
        "slot_ms",
        "cad_symbols",
        "settle",
        "timings",
        "ledger",
        "ledger_worst_case",
    ]
    assert estimate["settle"] == {"quiet_seconds": 4.313, "min_seconds": 25.0, "max_seconds": 120.0}
    assert list(estimate["timings"][0]) == [
        "links",
        "deadline_typical",
        "deadline_worst_case",
        "longest_run_typical",
        "longest_run_worst_case",
    ]
    ledger_keys = [
        "cw",
        "window_seconds",
        "budget_seconds",
        "spurious_factor",
        "gateway_seconds",
        "gateway_unanswered_seconds",
        "relay_seconds",
        "relay_largest_replies_seconds",
        "destination_seconds",
        "fits",
        "per_window",
    ]
    assert list(estimate["ledger"]) == ledger_keys
    assert list(estimate["ledger_worst_case"]) == ledger_keys
    assert estimate["ledger"] == {
        "cw": 7,
        "window_seconds": 3600,
        "budget_seconds": 36.0,
        "spurious_factor": 1.0,
        "gateway_seconds": 1.282,
        "gateway_unanswered_seconds": 3.846,
        "relay_seconds": 3.138,
        "relay_largest_replies_seconds": 5.595,
        "destination_seconds": 1.855,
        "fits": True,
        "per_window": 11,
    }
    worst = estimate["ledger_worst_case"]
    assert (worst["cw"], worst["spurious_factor"], worst["gateway_seconds"]) == (8, 1.471, 1.886)
    assert (worst["relay_seconds"], worst["per_window"]) == (4.614, 7)
    assert json.dumps(document)
    assert not [item for item in _walk(document) if isinstance(item, bytes)]


def test_json_g2() -> None:
    document: Any = plan_to_json(_g2())

    assert document["verdict"] == "allowed"
    assert document["firmware"]["version"] == "2.7.11"
    assert document["gateway"]["node"] is None
    assert document["gateway"]["authorization"] == "not_checked"
    assert document["estimate"]["ledger"]["fits"] is True
    assert document["estimate"]["ledger_worst_case"]["fits"] is False
    assert document["estimate"]["ledger"]["per_window"] == 1
    assert document["estimate"]["ledger_worst_case"]["per_window"] == 0


def test_json_without_estimate() -> None:
    document: Any = plan_to_json(_plan(region="EU_433"))

    assert document["estimate"] is None
    assert isinstance(document["requests"], list)


def test_json_with_an_air_util_reading() -> None:
    destination = Destination(
        "!deadbe01",
        True,
        template_managed=True,
        firmware="2.8.3",
        air_util_tx=AirUtilReading(1.23456, 61.2349),
    )

    document: Any = plan_to_json(_plan(destination=destination))

    assert document["destination_air_util_tx"] == {"percent": 1.235, "age_seconds": 61.235}


def test_text_has_no_rst() -> None:
    for plan in (_plan(), _g2(), _g3()):
        text = render_text(plan)
        assert "``" not in text
        assert ":class:" not in text
