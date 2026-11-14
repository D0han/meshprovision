"""``mesh remote diff``'s command shape and its small pure helpers."""

from __future__ import annotations

from datetime import UTC, datetime

import click
import pytest

from meshprovision.cli import remote as remote_cli
from meshprovision.cli.remote import remote
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import ManagementMode
from meshprovision.health.history import NodeHistory, TelemetryPoint
from meshprovision.nodeid import NodeId
from meshprovision.remote.plan import (
    SECTION_CHOICES,
)
from meshprovision.remote.plan_types import (
    AirUtilReading,
)

pytestmark = pytest.mark.unit

NODE = NodeId.from_hex("deadbe01")
GATEWAY = NodeId.from_hex("deadbe0a")
KEY_A = bytes(range(32))
KEY_B = bytes(range(1, 33))


def test_the_remote_group_has_only_diff() -> None:
    assert sorted(remote.commands) == ["diff"]


def test_diff_has_exactly_these_options() -> None:
    diff = remote.commands["diff"]

    assert {param.name for param in diff.params} == {
        "node",
        "dry_run",
        "gateway",
        "sections",
        "json_output",
    }
    assert {opt for param in diff.params for opt in param.opts if opt.startswith("--")} == {
        "--dry-run",
        "--gateway",
        "--section",
        "--json",
    }
    assert not [param.name for param in diff.params if getattr(param, "hidden", False)]


def test_section_choices_are_the_plan_choices() -> None:
    section = next(p for p in remote.commands["diff"].params if p.name == "sections")

    assert isinstance(section.type, click.Choice)
    assert tuple(section.type.choices) == SECTION_CHOICES


def test_air_util_tx_reading() -> None:
    history = NodeHistory(
        node=NODE,
        telemetry=(
            TelemetryPoint(900.0, air_util_tx=1.0),
            TelemetryPoint(950.0, air_util_tx=2.5),
            TelemetryPoint(990.0),
        ),
    )

    reading = remote_cli._air_util_tx(history, now=1000.0)

    assert reading == AirUtilReading(2.5, 50.0)


def test_air_util_tx_reading_of_an_empty_history() -> None:
    assert remote_cli._air_util_tx(NodeHistory(node=NODE), now=1000.0) is None


def test_air_util_tx_reading_of_a_future_point_has_age_zero() -> None:
    history = NodeHistory(node=NODE, telemetry=(TelemetryPoint(2000.0, air_util_tx=3.0),))

    assert remote_cli._air_util_tx(history, now=1000.0) == AirUtilReading(3.0, 0.0)


def test_destination_and_gateway_facts() -> None:
    public_keys = {"deadbe0a_pub": KEY_A, "other_pub": KEY_B}
    record = NodeRecord(
        node_id="deadbe01",
        management=ManagementMode.TEMPLATE,
        firmware_version="2.8.3.abc",
        authorized_admin_keys=("deadbe0a_pub", "missing_ref"),
    )
    gateway_record = NodeRecord(node_id="deadbe0a", firmware_version="2.7.26")
    reading = AirUtilReading(1.0, 2.0)

    destination = remote_cli._destination(NODE, record, public_keys, reading)
    gateway = remote_cli._gateway(GATEWAY, gateway_record, public_keys)

    assert destination.label == "!deadbe01"
    assert destination.found is True
    assert destination.template_managed is True
    assert destination.firmware == "2.8.3.abc"
    assert destination.authorized_keys == frozenset({KEY_A})
    assert destination.air_util_tx == reading
    assert gateway.label == "!deadbe0a"
    assert gateway.found is True
    assert gateway.public_key == KEY_A
    assert gateway.firmware == "2.7.26"


def test_an_observed_archived_or_missing_row() -> None:
    observed = NodeRecord(node_id="deadbe01")
    archived = NodeRecord(node_id="deadbe01", archived_at=datetime(2026, 1, 1, tzinfo=UTC))

    assert remote_cli._destination(NODE, observed, {}, None).template_managed is False
    assert remote_cli._destination(NODE, observed, {}, None).archived is False
    assert remote_cli._destination(NODE, archived, {}, None).archived is True
    assert remote_cli._destination(NODE, None, {}, None).found is False
    assert remote_cli._gateway(GATEWAY, None, {}).found is False
    assert remote_cli._gateway(GATEWAY, NodeRecord(node_id="deadbe0a"), {}).public_key is None
    assert remote_cli._gateway(GATEWAY, NodeRecord(node_id="deadbe0a"), {}).archived is False
    assert remote_cli._gateway(GATEWAY, archived, {}).archived is True
