"""Preset-aware rules: chatty limits by airtime, long presets on crowded meshes."""

from __future__ import annotations

import io
from datetime import UTC, datetime, timedelta

import pytest
from rich.console import Console

from meshprovision.cli.common import template_hints
from meshprovision.config.template import load_template_text
from meshprovision.datasources.base import SOURCE_LORANET, SOURCE_LORASTATS
from meshprovision.datasources.models import NodeObservation
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import ManagementMode
from meshprovision.health import render
from meshprovision.health.metrics import NodeMetrics
from meshprovision.health.report import HealthReport, assess_nodes
from meshprovision.health.rules import (
    CHATTY_MAX_PER_HOUR,
    CHATTY_MIN_PER_HOUR,
    CHATTY_PER_HOUR,
    CHATTY_REFERENCE_PRESET,
    LONG_PRESET_MAX_NODES,
    LONG_PRESETS,
    PRESET_AIRTIME_MS,
    Importance,
    NodeContext,
    advise,
    chatty_limit,
)
from meshprovision.nodeid import NodeId
from meshprovision.status.merge import MergedNode, merge_observations
from meshprovision.status.report import StatusOptions, build_report

pytestmark = pytest.mark.unit

_NODE = NodeId.from_hex("ab446357")
_OTHER = NodeId.from_hex("979ed146")
_NOW = 1_760_994_000.0
_SEEN = datetime.fromtimestamp(_NOW, tz=UTC)
_LOW = Importance("low", 0)


def _m(**fields: object) -> NodeMetrics:
    base: dict[str, object] = {
        "node": _NODE,
        "days": 7,
        "window_start": _NOW - 7 * 86400,
        "now": _NOW,
        "covered_hours": 24,
        "last_heard": _NOW - 60,
    }
    base.update(fields)
    return NodeMetrics(**base)  # type: ignore[arg-type]


def _advice(metrics: NodeMetrics, **context: object) -> dict[str, str]:
    found = advise(metrics, NodeContext(**context), _LOW)  # type: ignore[arg-type]
    return {advice.code: advice.text for advice in found}


def test_the_constants_are_the_documented_ones() -> None:
    assert (CHATTY_PER_HOUR, CHATTY_MIN_PER_HOUR, CHATTY_MAX_PER_HOUR) == (2.0, 1.0, 6.0)
    assert (CHATTY_REFERENCE_PRESET, LONG_PRESET_MAX_NODES) == ("LONG_FAST", 60)
    assert dict(PRESET_AIRTIME_MS) == {
        "SHORT_TURBO": 23,
        "SHORT_FAST": 45,
        "SHORT_SLOW": 85,
        "MEDIUM_TURBO": 80,
        "MEDIUM_FAST": 160,
        "MEDIUM_SLOW": 300,
        "LONG_TURBO": 378,
        "LONG_FAST": 559,
        "LONG_MODERATE": 1642,
        "LONG_SLOW": 3023,
    }
    assert (
        frozenset({"LONG_FAST", "LONG_MODERATE", "LONG_SLOW", "LONG_TURBO", "VERY_LONG_SLOW"})
        == LONG_PRESETS
    )


# ---------------------------------------------------------------------------
# chatty_limit: the airtime of 2 packets an hour on LONG_FAST.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("preset", "limit"),
    [
        ("LONG_FAST", 2.0),
        ("LONG_TURBO", 2 * 559 / 378),
        ("MEDIUM_SLOW", 2 * 559 / 300),
        ("MEDIUM_FAST", 6.0),
        ("SHORT_FAST", 6.0),
        ("LONG_MODERATE", 1.0),
        ("LONG_SLOW", 1.0),
        (None, 2.0),
        ("VERY_LONG_SLOW", 2.0),
        ("12", 2.0),
    ],
)
def test_chatty_limit_is_an_airtime_budget(preset: str | None, limit: float) -> None:
    assert chatty_limit(preset) == pytest.approx(limit)


# ---------------------------------------------------------------------------
# advise: position and telemetry limits, the preset named.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("preset", "limit", "named"),
    [
        ("LONG_FAST", 2.0, "on LONG_FAST"),
        ("MEDIUM_FAST", 6.0, "on MEDIUM_FAST"),
        ("LONG_MODERATE", 1.0, "on LONG_MODERATE"),
        (None, 2.0, "on LONG_FAST, assumed"),
    ],
)
def test_position_advice_starts_above_the_preset_limit(
    preset: str | None, limit: float, named: str
) -> None:
    assert "position_interval" not in _advice(_m(positions_per_hour=limit), preset=preset)
    text = _advice(_m(positions_per_hour=limit + 0.01), preset=preset)["position_interval"]
    assert text == (
        f"at least {limit + 0.01:.1f} position packets an hour (more than {limit:.1f} an hour "
        f"{named}): consider a longer position interval or smart position"
    )


def test_telemetry_advice_needs_a_busy_channel_and_the_preset_limit() -> None:
    busy = {"channel_utilization": 30.0}
    assert "telemetry_interval" not in _advice(
        _m(telemetry_per_hour=6.0, **busy), preset="MEDIUM_FAST"
    )
    text = _advice(_m(telemetry_per_hour=6.5, **busy), preset="MEDIUM_FAST")["telemetry_interval"]
    assert text == (
        "at least 6.5 telemetry packets an hour on a busy channel (more than 6.0 an hour on "
        "MEDIUM_FAST): consider a longer telemetry interval"
    )
    assert "telemetry_interval" not in _advice(_m(telemetry_per_hour=6.5), preset="MEDIUM_FAST")


# ---------------------------------------------------------------------------
# advise: a long preset on a crowded mesh.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("preset", "online", "suggested"),
    [
        ("LONG_FAST", 61, True),
        ("LONG_FAST", 60, False),
        ("VERY_LONG_SLOW", 61, True),
        ("LONG_MODERATE", 200, True),
        ("MEDIUM_FAST", 200, False),
        ("LONG_FAST", None, False),
        (None, 200, False),
    ],
)
def test_a_long_preset_on_a_crowded_mesh_is_suggested_a_faster_one(
    preset: str | None, online: int | None, suggested: bool
) -> None:
    found = _advice(_m(), preset=preset, online_local_nodes=online)
    assert ("preset_congested" in found) is suggested


def test_the_preset_suggestion_text() -> None:
    found = _advice(_m(), preset="LONG_FAST", online_local_nodes=75)
    assert found["preset_congested"] == (
        "75 nodes online around it on LONG_FAST: a mesh of more than 60 nodes is better served "
        "by a faster preset such as MEDIUM_FAST (a change for the whole mesh, not for this node "
        "alone)"
    )


# ---------------------------------------------------------------------------
# merge: the preset and the online count, the template's preset as a fallback.
# ---------------------------------------------------------------------------

_NOW_DT = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)


def _obs(source: str, age_minutes: int, **fields: object) -> NodeObservation:
    return NodeObservation(
        node_id=_NODE,
        source=source,
        observed_at=_NOW_DT,
        last_seen=_NOW_DT - timedelta(minutes=age_minutes),
        **fields,  # type: ignore[arg-type]
    )


def test_the_newest_observed_preset_and_online_count_win() -> None:
    node = merge_observations(
        _NODE,
        [
            _obs(SOURCE_LORANET, 30, modem_preset="LONG_FAST", online_local_nodes=12),
            _obs(SOURCE_LORASTATS, 5, modem_preset="MEDIUM_FAST", online_local_nodes=70),
        ],
        now=_NOW_DT,
        template_preset="SHORT_FAST",
    )
    assert (node.modem_preset, node.online_local_nodes) == ("MEDIUM_FAST", 70)


def test_the_template_preset_fills_in_only_when_no_source_reports_one() -> None:
    observed = merge_observations(_NODE, [_obs(SOURCE_LORANET, 5)], now=_NOW_DT)
    filled = merge_observations(
        _NODE, [_obs(SOURCE_LORANET, 5)], now=_NOW_DT, template_preset="SHORT_FAST"
    )
    unseen = merge_observations(_NODE, [], now=_NOW_DT, template_preset="SHORT_FAST")
    assert (observed.modem_preset, filled.modem_preset, unseen.modem_preset) == (
        None,
        "SHORT_FAST",
        "SHORT_FAST",
    )


def test_the_json_carries_the_preset_and_the_online_count() -> None:
    node = merge_observations(
        _NODE,
        [_obs(SOURCE_LORANET, 5, region="EU_868", modem_preset="LONG_FAST", online_local_nodes=9)],
        now=_NOW_DT,
    )
    document = node.to_json_dict()
    keys = list(document)
    assert keys[keys.index("region") + 1] == "modem_preset"
    assert keys[keys.index("air_util_tx") + 1] == "online_local_nodes"
    assert (document["modem_preset"], document["online_local_nodes"]) == ("LONG_FAST", 9)


def test_build_report_gives_the_template_preset_to_template_managed_nodes_only() -> None:
    records = {
        _NODE: NodeRecord(node_id=_NODE.hex, management=ManagementMode.TEMPLATE),
        _OTHER: NodeRecord(node_id=_OTHER.hex, management=ManagementMode.OBSERVED),
    }
    report = build_report(
        records=records,
        observations_by_source={},
        node_ids=[_NODE, _OTHER],
        now=_NOW_DT,
        options=StatusOptions(template_preset="MEDIUM_FAST"),
    )
    assert [node.modem_preset for node in report.nodes] == ["MEDIUM_FAST", None]
    plain = build_report(
        records=records, observations_by_source={}, node_ids=[_NODE, _OTHER], now=_NOW_DT
    )
    assert [node.modem_preset for node in plain.nodes] == [None, None]


# ---------------------------------------------------------------------------
# The health report, the detail and the JSON.
# ---------------------------------------------------------------------------


def _health_report(preset: str | None, online: int | None) -> HealthReport:
    node = MergedNode(
        node_id=_NODE,
        last_seen=_SEEN,
        age=timedelta(0),
        modem_preset=preset,
        online_local_nodes=online,
    )
    nodes = assess_nodes([node], {}, fleet=[_NODE], now=_NOW, days=7)
    return HealthReport(generated_at=_SEEN, days=7, fetched=False, nodes=nodes)


def test_assess_nodes_passes_the_preset_and_the_online_count_to_the_rules() -> None:
    (health,) = _health_report("LONG_FAST", 80).nodes
    assert [advice.code for advice in health.advice] == ["preset_congested"]


def _detail(report: HealthReport) -> str:
    buffer = io.StringIO()
    Console(file=buffer, width=250, color_system=None).print(render.build_detail(report))
    return buffer.getvalue()


def test_the_detail_shows_the_preset_and_its_limit() -> None:
    assert (
        "Preset: MEDIUM_FAST, 80 nodes online around it; more than 6.0 telemetry or position "
        "packets an hour are suggested to be reduced" in _detail(_health_report("MEDIUM_FAST", 80))
    )
    assert (
        "Preset: unknown (LONG_FAST assumed); more than 2.0 telemetry or position packets an "
        "hour are suggested to be reduced" in _detail(_health_report(None, None))
    )


def test_the_health_json_carries_the_preset_and_the_online_count() -> None:
    (node,) = render.health_to_json_dict(_health_report("LONG_FAST", 80))["nodes"]  # type: ignore[misc]
    keys = list(node)
    at = keys.index("offline_after_seconds")
    assert keys[at + 1 : at + 3] == ["modem_preset", "online_local_nodes"]
    assert (node["modem_preset"], node["online_local_nodes"]) == ("LONG_FAST", 80)


# ---------------------------------------------------------------------------
# template_hints: what the CLIs take from the template.
# ---------------------------------------------------------------------------

_TEMPLATE = """
device:
  role: {role}
  node_info_broadcast_secs: {secs}
lora:
  region: EU_868
  use_preset: {use_preset}
  modem_preset: MEDIUM_FAST
"""


def test_template_hints_without_a_template() -> None:
    assert template_hints(None) == (None, None)


def test_template_hints_take_the_interval_and_the_preset() -> None:
    template = load_template_text(_TEMPLATE.format(role="CLIENT", secs=21600, use_preset="true"))
    assert template_hints(template) == (timedelta(hours=6), "MEDIUM_FAST")


def test_template_hints_without_use_preset_have_no_preset() -> None:
    template = load_template_text(_TEMPLATE.format(role="TAK", secs=0, use_preset="false"))
    assert template_hints(template) == (timedelta(hours=24), None)
